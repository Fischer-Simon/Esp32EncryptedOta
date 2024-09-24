#pragma once

#include <WiFiServer.h>
#include <cstdint>
#include <mbedtls/aes.h>
#include <MD5Builder.h>
#include <EEPROM.h>

class Esp32EncryptedOta {
public:
    static const int ChunkSize = 1024;
    static const int SectorsPerBlock = 16;
    static const int FlashBlockSize = SPI_FLASH_SEC_SIZE * SectorsPerBlock;

    static const int AesIvSize = 16;
    static const int AesKeySize = 16;
    static const int AuthTokenSize = 16;
    static const char AuthToken[16];

    enum class ProgramState : uint8_t {
        New,
        Unstable,
        Stable,
        UpdatePending,
    };

    typedef void(*callback_t)();
    typedef void(*set_state_t)(ProgramState);
    typedef ProgramState(*get_state_t)();

    explicit Esp32EncryptedOta(int port, set_state_t setProgramState, get_state_t getProgramState, callback_t onComplete = nullptr);

    /**
     * Set the aes key to use for encryption. Must be a 32 character long hex string.
     * @param aesKey
     * @return
     */
    bool setAesKey(const char* aesKey);

    void loop();

    /**
     * Indicates whether the program should start into a recovery mode where only the ota functionality is running.
     * This is true on two occasions:
     * 1. The ota client requested an update.
     * 2. The controller restarted without marking the program as good.
     * @see Esp32EncryptedOta::markProgramAsStable()
     * @return
     */
    bool shouldStartRecoveryMode() const;

    void setRecoveryMode();

    void markProgramStable();

private:
    struct UpdateHeader {
        const uint8_t authToken[AuthTokenSize];
        const uint8_t firmwareMd5Hash[32]; // hex string
        uint32_t firmwareSize; // size in bytes
        uint8_t updateType; // f = firmware or d = data
        const uint8_t padding[11]; // pad to full 16 bytes
    };
    static_assert(sizeof(UpdateHeader) < SPI_FLASH_SEC_SIZE, "UpdateHeader too large");

    enum class Status : uint8_t {
        Ok = 0,
        Error = 1,
        SendSectors = 2,
        Blocking = 3, // Only used by the python script
        RestartPending = 4,
        Done = 10,
    };

    void setProgramState(ProgramState);

    void doUpdate();

    bool readHeader();

    void receiveBlockData();

    void statusMessage(Status status, const char* msg = "");

    WiFiServer m_updateServer;
    WiFiClient m_updateClient;

    ProgramState m_programState{ProgramState::New};
    bool m_isInRecovery{false};
    bool m_shouldBootRecovery{false};

    uint8_t m_updateType{0};
    const esp_partition_t* m_partition = nullptr;
    MD5Builder m_md5{};
    std::unique_ptr<uint8_t> m_updateBuffer{};
    std::unique_ptr<uint8_t> m_decryptionBuffer{};
    uint32_t m_uploadSize{};
    uint8_t m_expectedFirmwareMd5[33]{};
    uint8_t m_aesKey[AesKeySize]{};
    uint8_t m_aesIv[AesIvSize]{};
    mbedtls_aes_context m_aesContext{};
    callback_t m_onComplete{nullptr};
    set_state_t m_setProgramState{nullptr};
    get_state_t m_getProgramState{nullptr};

    bool eraseFlash();
};
