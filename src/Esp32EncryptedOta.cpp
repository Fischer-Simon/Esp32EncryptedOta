#include "Esp32EncryptedOta.h"

#include <WiFi.h>
#include <Update.h>
#include <esp_task_wdt.h>
#include <esp_bt.h>
#include <esp_ota_ops.h>
#include <Ansi.h>

// This token does not need to be secure. It is just used to validate the aes encryption key.
const char Esp32EncryptedOta::AuthToken[16] = {'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                               'a'};

char Ansi::ansiBuffer[32];

void hextobin(unsigned char *out, const char *hexString, size_t n) {
    int i;
    char _t[3];
    const char *p = hexString;
    for (i = 0; i < n; ++i) {
        memcpy(_t, p, 2);
        _t[2] = '\0';
        out[i] = (int) strtol(_t, nullptr, 16);
        p += 2;
    }
}

Esp32EncryptedOta::Esp32EncryptedOta(int port, set_state_t setProgramStateCb, get_state_t getProgramStateCb, callback_t onComplete) :
        m_setProgramState{setProgramStateCb},
        m_getProgramState{getProgramStateCb},
        m_onComplete{onComplete} {
    m_updateServer.begin(port);
    m_programState = m_getProgramState();
    m_shouldBootRecovery = m_programState == ProgramState::Unstable || m_programState == ProgramState::UpdatePending;
    if (m_programState == ProgramState::New) {
        setProgramState(ProgramState::Unstable);
    }
}

bool Esp32EncryptedOta::setAesKey(const char *aesKey) {
    if (strlen(aesKey) != 32) {
        return false;
    }

    hextobin(m_aesKey, aesKey, AesKeySize);
    return true;
}

void Esp32EncryptedOta::loop() {
    if (!(m_updateClient = m_updateServer.accept())) {
        return;
    }

    m_updateClient.setNoDelay(true);
    m_updateClient.setTimeout(4);
    m_updateBuffer.reset(new uint8_t[SPI_FLASH_SEC_SIZE]);
    m_decryptionBuffer.reset(new uint8_t[SPI_FLASH_SEC_SIZE]);
    doUpdate();
    m_updateBuffer = nullptr;
    m_decryptionBuffer = nullptr;
}

bool Esp32EncryptedOta::shouldStartRecoveryMode() const {
    return m_shouldBootRecovery;
}

void Esp32EncryptedOta::setRecoveryMode() {
    m_isInRecovery = true;
}

void Esp32EncryptedOta::markProgramStable() {
    setProgramState(ProgramState::Stable);
}

void Esp32EncryptedOta::setProgramState(ProgramState state) {
    if (m_programState == state) {
        return;
    }
    m_setProgramState(state);
    m_programState = state;
}

void Esp32EncryptedOta::doUpdate() {
    if (!readHeader()) {
        return;
    }

    if (!eraseFlash()) {
        return;
    }

    receiveBlockData();
}

bool Esp32EncryptedOta::readHeader() {
    if (m_updateClient.readBytes(m_updateBuffer.get(), sizeof(UpdateHeader) + AesIvSize) != sizeof(UpdateHeader) + AesIvSize) {
        statusMessage(Status::Error, "Unable to read header\n");
        return false;
    }

    mbedtls_aes_setkey_dec(&m_aesContext, m_aesKey, AesKeySize * 8);

    memcpy(m_aesIv, m_updateBuffer.get(), AesIvSize);

    // decrypt the authentication token
    mbedtls_aes_crypt_cbc(&m_aesContext, MBEDTLS_AES_DECRYPT, sizeof(UpdateHeader),
                          m_aesIv, m_updateBuffer.get() + AesIvSize,
                          m_decryptionBuffer.get());

    auto *updateHeader = reinterpret_cast<UpdateHeader *>(m_decryptionBuffer.get());

    if (memcmp(AuthToken, updateHeader->authToken, AuthTokenSize) != 0) {
        statusMessage(Status::Error, "Incorrect authentication token\n");
        return false;
    }

    if (updateHeader->updateType == 'r') {
        // Requested recovery
        if (m_isInRecovery) {
            statusMessage(Status::RestartPending, "Already in recovery\n");
            return false;
        }
        setProgramState(ProgramState::UpdatePending);
        m_updateServer.stop();
        statusMessage(Status::RestartPending, "Rebooting into recovery\n");
        esp_task_wdt_delete(nullptr);
        ESP.restart();
    }

    if (updateHeader->updateType != 'f' && updateHeader->updateType != 'd') {
        statusMessage(Status::Error, "Invalid update type\n");
        return false;
    }

    memcpy(m_expectedFirmwareMd5, updateHeader->firmwareMd5Hash, 32);
    m_expectedFirmwareMd5[32] = 0;

    if (updateHeader->updateType == 'f') {
        m_partition = esp_ota_get_next_update_partition(nullptr);
    } else {
        m_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, nullptr);
    }
    if (!m_partition) {
        statusMessage(Status::Error, "Unable to find suitable partition\n");
        return false;
    }
    if (updateHeader->firmwareSize > m_partition->size) {
        char printfBuffer[256];
        snprintf(printfBuffer, sizeof(printfBuffer), "Flash data too large: firmware_size=%i; partition_size=%i\n", updateHeader->firmwareSize, m_partition->size);
        statusMessage(Status::Error, printfBuffer);
        return false;
    }

    m_updateType = updateHeader->updateType;

    m_md5.begin();
    m_uploadSize = updateHeader->firmwareSize;

    statusMessage(Status::Ok, "Header ok\n");
    return true;
}

bool Esp32EncryptedOta::eraseFlash() {
    uint32_t blockCount = m_uploadSize / FlashBlockSize + ((m_uploadSize % FlashBlockSize != 0) ? 1 : 0);
    char printfBuffer[256];
    statusMessage(Status::Ok, "Erasing...   [" ANSI_CURSOR_SAVE);
    statusMessage(Status::Ok, Ansi::cursorRight(static_cast<int>(blockCount)));
    statusMessage(Status::Ok, "]" ANSI_CURSOR_RESTORE);
    auto duration = millis();
    for (uint32_t block = 0; block < blockCount; block++) {
        uint32_t blockOffset = block * FlashBlockSize;
        uint32_t blockSize = (blockOffset + FlashBlockSize >= m_uploadSize) ? (m_uploadSize - blockOffset)
                                                                            : FlashBlockSize;
        esp_err_t ret = esp_partition_erase_range(m_partition, blockOffset, blockSize);
        if (ret != ESP_OK) {
            snprintf(printfBuffer, sizeof(printfBuffer), "ESP partition erase error %i\n", ret);
            statusMessage(Status::Error, printfBuffer);
            return false;
        }
        esp_task_wdt_reset();
        statusMessage(Status::Ok, "#");
    }
    duration = millis() - duration;

    snprintf(printfBuffer, sizeof(printfBuffer), ANSI_CURSOR_RIGHT(3) ANSI_TEXT_STYLE2(ANSI_BOLD, ANSI_FG_GREEN) "Done" ANSI_TEXT_STYLE("0") ". %lu kb/s\n", m_uploadSize / duration);
    statusMessage(Status::Ok, printfBuffer);
    return true;
}

void Esp32EncryptedOta::receiveBlockData() {
    char printfBuffer[256];
    esp_err_t ret;
    uint32_t blockCount = m_uploadSize / FlashBlockSize + ((m_uploadSize % FlashBlockSize != 0) ? 1 : 0);
    statusMessage(Status::Ok, "Flashing...  [" ANSI_CURSOR_SAVE);
    statusMessage(Status::Ok, Ansi::cursorRight(static_cast<int>(blockCount)));
    statusMessage(Status::SendSectors, "]" ANSI_CURSOR_RESTORE);
    auto duration = millis();
    for (uint32_t block = 0; block < blockCount; block++) {
        uint32_t blockOffset = block * FlashBlockSize;
        uint32_t blockSize = (blockOffset + FlashBlockSize > m_uploadSize) ? (m_uploadSize - blockOffset)
                                                                            : FlashBlockSize;
        for (int chunkOffset = 0; chunkOffset < blockSize; chunkOffset += ChunkSize) {
            uint32_t offset = blockOffset + chunkOffset;
            if (m_updateClient.readBytes(m_updateBuffer.get(), ChunkSize) != ChunkSize) {
                statusMessage(Status::Error, "\nFailed to receive sector data\n");
                return;
            }
            mbedtls_aes_crypt_cbc(&m_aesContext, MBEDTLS_AES_DECRYPT, ChunkSize, m_aesIv,
                                  m_updateBuffer.get(),
                                  m_decryptionBuffer.get());
            ret = esp_partition_write(m_partition, offset, m_decryptionBuffer.get(), ChunkSize);
            if (ret != ESP_OK) {
                snprintf(printfBuffer, sizeof(printfBuffer), "ESP partition write error %i\n", ret);
                statusMessage(Status::Error, printfBuffer);
                return;
            }
            esp_task_wdt_reset();
        }
        statusMessage(Status::Ok, "#");
    }
    duration = millis() - duration;

    snprintf(printfBuffer, sizeof(printfBuffer), ANSI_CURSOR_RIGHT(3)  ANSI_TEXT_STYLE2(ANSI_BOLD, ANSI_FG_GREEN) "Done" ANSI_TEXT_STYLE("0") ". %lu kb/s\n", m_uploadSize / duration);
    statusMessage(Status::Ok, printfBuffer);

    statusMessage(Status::Ok, "Verifying... [" ANSI_CURSOR_SAVE);
    statusMessage(Status::Ok, Ansi::cursorRight(static_cast<int>(blockCount)));
    statusMessage(Status::Ok, "]" ANSI_CURSOR_RESTORE);

    duration = millis();
    m_md5.begin();
    for (uint32_t offset = 0; offset < m_uploadSize; offset += SPI_FLASH_SEC_SIZE) {
        esp_partition_read(m_partition, offset, m_updateBuffer.get(), SPI_FLASH_SEC_SIZE);
        m_md5.add(m_updateBuffer.get(), SPI_FLASH_SEC_SIZE);
        if (offset % FlashBlockSize == 0) {
            statusMessage(Status::Ok, "#");
        }
    }
    m_md5.calculate();
    m_md5.getChars(reinterpret_cast<char *>(m_updateBuffer.get()));

    duration = millis() - duration;

    snprintf(printfBuffer, sizeof(printfBuffer), ANSI_CURSOR_RIGHT(3)  ANSI_TEXT_STYLE2(ANSI_BOLD, ANSI_FG_GREEN) "Done" ANSI_TEXT_STYLE("0") ". %lu kb/s\n", m_uploadSize / duration);
    statusMessage(Status::Ok, printfBuffer);

    if (memcmp(m_updateBuffer.get(), m_expectedFirmwareMd5, sizeof(m_expectedFirmwareMd5)) == 0) {
        Serial.println("Ok");
        statusMessage(Status::Ok, "MD5 verified, update ok\n");
    } else {
        Serial.println("Error");
        statusMessage(Status::Error, "MD5 mismatch\n");
        return;
    }

    if (m_updateType == 'f' && esp_ota_set_boot_partition(m_partition) != ESP_OK) {
        statusMessage(Status::Error, "Unable to activate boot partition\n");
        return;
    }
    m_updateServer.stop();
    statusMessage(Status::Done, "\nFlashing complete, rebooting.\n");
    if (m_onComplete) {
        m_onComplete();
    }
    delay(100);
    setProgramState(ProgramState::New);
    esp_task_wdt_delete(nullptr);
    ESP.restart();
}

void Esp32EncryptedOta::statusMessage(Status status, const char *msg) {
    int msgLength = static_cast<int>(strlen(msg));
    Serial.print(msg);
    m_updateClient.write((uint8_t) status);
    m_updateClient.write(reinterpret_cast<const char *>(&msgLength), sizeof(msgLength));
    m_updateClient.print(msg);
    if (status == Status::Error || status == Status::Done || status == Status::RestartPending) {
        m_updateClient.readBytes(m_updateBuffer.get(), 1);
        delay(200);
        m_updateClient.stop();
    }
}
