 /* USER CODE BEGIN Header */
/**
 * @file           : main.c
 * @brief          : Main program body
 * @attention
 *
 * Copyright (c) 2025 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "fatfs.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "fatfs_sd.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha256.h"
#include "pbkdf2.h"
#include "aes.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
// dinh nghia va bien
/* USER CODE BEGIN PD */
#define UART_RX_BUFFER_SIZE 1024    //Kích thu?c b? d?m nh?n d? li?u UART là 1024 byte.
#define MAX_FILENAME_LEN 64         //Ð? dài t?i da c?a tên t?p 
#define CHUNK_SIZE 16              // Kích thu?c kh?i d? li?u du?c x? lý m?i l?n
#define FLASH_STORAGE_ADDRESS 0x0800FC00       // dia chi luu khoa
#define STRING_STORED_FLAG_ADDRESS (FLASH_STORAGE_ADDRESS + 64) // luu co kiem tra da ghi vao flash chua
#define UID_LENGTH 12
#define SALT_LENGTH 8
#define PBKDF2_ITERATIONS 1000     // so lan lap
#define AES_KEY_LENGTH 16
#define PLAINTEXT_LENGTH 16
#define SHA256_LENGTH 32    /// do dai dau ra ham SHA
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
SPI_HandleTypeDef hspi1;
UART_HandleTypeDef huart1;

/* USER CODE BEGIN PV */
// bien toan cuc
FATFS fs;
FIL fil;
FRESULT fresult;
UINT br, bw;

char uart_rx_buffer[UART_RX_BUFFER_SIZE];      // bo nho dem uart
uint16_t uart_rx_index = 0;            // chi so theo doi vi tri UART
char filename[MAX_FILENAME_LEN];
uint32_t expected_file_size = 0;
uint32_t received_file_size = 0;
char aes_key_hex[33];    // dang hex
uint8_t aes_key_bin[16];  //dang nhi phan
char iv_hex[33];          // lu IV 
int file_opened = 0;
uint8_t derived_key[AES_KEY_LENGTH];  // khoa dc tao tu UID
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_SPI1_Init(void);
/* USER CODE BEGIN PFP */
static void send_uart(const char *str);
static void uart_rx_buffer_clear(void);
static int hexstr_to_bytes(const char *hexstr, uint8_t *buf, int max_len);
static int open_file_for_write(const char *fname);
static int write_chunk_to_file(const uint8_t *data, uint16_t len, const uint8_t *sha256);
static void close_file(void);
static void process_command(char *cmd);
static void read_file(const char *fname);
static void write_string_to_flash(const char *str);
static void read_string_from_flash(char *buffer, uint32_t max_len);
static int is_string_stored(void);
static void read_uid(uint8_t *uid);
static void generate_key_from_uid(void);
static void derive_key_hex(const char *password, char *key_hex);
static void compute_sha256(const uint8_t *input, uint32_t input_len, uint8_t *hash_output);
static int verify_sha256(const uint8_t *data, uint32_t data_len, const uint8_t *expected_sha256);
static void hash_to_hex(uint8_t *hash, char *hex_output);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
// ham gui qua UART
static void send_uart(const char *str) {
    HAL_UART_Transmit(&huart1, (uint8_t*)str, strlen(str), HAL_MAX_DELAY);
}
// doc UID o vi tri 0x1FFFF7E8
static void read_uid(uint8_t *uid) {
    uint32_t uid_base_addr = 0x1FFFF7E8;
    for (int i = 0; i < UID_LENGTH; i++) {
        uid[i] = *(volatile uint8_t*)(uid_base_addr + i);
    }
    char uid_hex[25];
    for (int i = 0; i < UID_LENGTH; i++) {
        sprintf(uid_hex + 2*i, "%02X", uid[i]);
    }
    uid_hex[24] = '\0';
    char uid_msg[50];
    snprintf(uid_msg, sizeof(uid_msg), "Device UID: %s\r\n", uid_hex);
    send_uart(uid_msg);
}
// tao khoa tu pass word luu trong flash
static void derive_key_hex(const char *password, char *key_hex) {
    uint8_t salt[SALT_LENGTH] = {'s', 'a', 'l', 't', '1', '2', '3', '4'};
    uint8_t key[AES_KEY_LENGTH];
    pbkdf2_sha256((const uint8_t *)password, strlen(password), salt, SALT_LENGTH, PBKDF2_ITERATIONS, key, AES_KEY_LENGTH);
    for (int i = 0; i < AES_KEY_LENGTH; i++) {
        sprintf(key_hex + 2*i, "%02x", key[i]);
    }
    key_hex[32] = '\0';
}
// tao khoa tu UID
static void generate_key_from_uid(void) {
    uint8_t uid[UID_LENGTH];
    read_uid(uid);
    uint8_t salt[SALT_LENGTH] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    pbkdf2_sha256(uid, UID_LENGTH, salt, SALT_LENGTH, PBKDF2_ITERATIONS, derived_key, AES_KEY_LENGTH);
    char key_hex[2 * AES_KEY_LENGTH + 1];
    for (int i = 0; i < AES_KEY_LENGTH; i++) {
        sprintf(key_hex + 2*i, "%02x", derived_key[i]);
    }
    key_hex[2 * AES_KEY_LENGTH] = '\0';
    char key_msg[100];
    snprintf(key_msg, sizeof(key_msg), "Derived AES key: %s\r\n", key_hex);
    // send_uart(key_msg);
}
// chuyen ban hssh thanh HEX
static void hash_to_hex(uint8_t *hash, char *hex_output) {
    for (int i = 0; i < SHA256_LENGTH; i++) {
        sprintf(hex_output + 2*i, "%02x", hash[i]);
    }
    hex_output[64] = '\0';
}
// tinh hash cua chunk du lieu
static void compute_sha256(const uint8_t *input, uint32_t input_len, uint8_t *hash_output) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, input_len);
    sha256_final(&ctx, hash_output);
}
// hash cua pass luwu trong flash 
static void computelogin_sha256(const char *input, char *hex_output) {
    uint8_t hash[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)input, strlen(input));
    sha256_final(&ctx, hash);
    hash_to_hex(hash, hex_output);
}

// xac thuwc hash kiem tra tinh toan ven du lieu
static int verify_sha256(const uint8_t *data, uint32_t data_len, const uint8_t *expected_sha256) {
    uint8_t computed_sha256[SHA256_LENGTH];
    compute_sha256(data, data_len, computed_sha256);
    return memcmp(computed_sha256, expected_sha256, SHA256_LENGTH) == 0;
}

static int is_string_stored(void) {
    uint16_t flag = *(volatile uint16_t*)STRING_STORED_FLAG_ADDRESS;
    return (flag == 0xA5A5);
}
// ma hoa bang uid va ghi vao flash = ECB
static void write_string_to_flash(const char *str) {
    uint8_t plaintext[PLAINTEXT_LENGTH] = {0};
    uint32_t len = strlen(str);
    if (len > PLAINTEXT_LENGTH - 1) len = PLAINTEXT_LENGTH - 1;
    memcpy(plaintext, str, len);
    uint8_t padding_len = PLAINTEXT_LENGTH - len;
    for (uint32_t i = len; i < PLAINTEXT_LENGTH; i++) {
        plaintext[i] = padding_len;
    }
    uint8_t ciphertext[PLAINTEXT_LENGTH];
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, derived_key);
    AES_ECB_encrypt(&ctx, plaintext);
    memcpy(ciphertext, plaintext, PLAINTEXT_LENGTH);
    HAL_FLASH_Unlock();
    FLASH_EraseInitTypeDef eraseInit;
    uint32_t pageError = 0;
    eraseInit.TypeErase = FLASH_TYPEERASE_PAGES;
    eraseInit.PageAddress = FLASH_STORAGE_ADDRESS;
    eraseInit.NbPages = 1;
    if (HAL_FLASHEx_Erase(&eraseInit, &pageError) != HAL_OK) {
        send_uart("ERROR: Flash erase failed\r\n");
        HAL_FLASH_Lock();
        return;
    }
    uint32_t address = FLASH_STORAGE_ADDRESS;
    for (uint32_t i = 0; i < PLAINTEXT_LENGTH; i += 2) {
        uint16_t data = (ciphertext[i] | (ciphertext[i + 1] << 8));
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_HALFWORD, address, data) != HAL_OK) {
            send_uart("ERROR: Flash write failed\r\n");
            HAL_FLASH_Lock();
            return;
        }
        address += 2;
    }
    if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_HALFWORD, STRING_STORED_FLAG_ADDRESS, 0xA5A5) != HAL_OK) {
        send_uart("ERROR: Flag write failed\r\n");
        HAL_FLASH_Lock();
        return;
    }
    HAL_FLASH_Lock();
    send_uart("OK: Encrypted string written to flash\r\n");
}
// doc va giai ma pass
static void read_string_from_flash(char *buffer, uint32_t max_len) {
    uint8_t ciphertext[PLAINTEXT_LENGTH];
    uint32_t address = FLASH_STORAGE_ADDRESS;
    for (uint32_t i = 0; i < PLAINTEXT_LENGTH; i++) {
        ciphertext[i] = *(volatile uint8_t*)address;
        address++;
    }
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, derived_key);
    AES_ECB_decrypt(&ctx, ciphertext);
    uint8_t padding_len = ciphertext[PLAINTEXT_LENGTH - 1];
    if (padding_len > 0 && padding_len <= PLAINTEXT_LENGTH) {
        for (uint32_t i = PLAINTEXT_LENGTH - padding_len; i < PLAINTEXT_LENGTH; i++) {
            if (ciphertext[i] != padding_len) {
                send_uart("ERROR: Invalid padding format\r\n");
                buffer[0] = '\0';
                return;
            }
        }
        uint32_t actual_len = PLAINTEXT_LENGTH - padding_len;
        if (actual_len < max_len) {
            memcpy(buffer, ciphertext, actual_len);
            buffer[actual_len] = '\0';
        } else {
            send_uart("ERROR: Decrypted string too long for buffer\r\n");
            buffer[0] = '\0';
        }
    } else {
        send_uart("ERROR: Invalid padding\r\n");
        buffer[0] = '\0';
    }
}
// xoa bo dem uart
static void uart_rx_buffer_clear(void) {
    memset(uart_rx_buffer, 0, UART_RX_BUFFER_SIZE);
    uart_rx_index = 0;
}

static int hexstr_to_bytes(const char *hexstr, uint8_t *buf, int max_len) {
    int len = strlen(hexstr);
    if (len % 2 != 0) return -1;
    int bytes_len = len / 2;
    if (bytes_len > max_len) return -1;
    for (int i = 0; i < bytes_len; i++) {
        sscanf(hexstr + 2*i, "%2hhx", &buf[i]);
    }
    return bytes_len;
}
// tao file va ghi UID vao dau file
static int open_file_for_write(const char *fname) {
    if (file_opened) {
        f_close(&fil);
        file_opened = 0;
    }
    fresult = f_open(&fil, fname, FA_WRITE | FA_CREATE_ALWAYS);
    if (fresult != FR_OK) {
        char msg[100];
        snprintf(msg, sizeof(msg), "ERROR: Failed to open file %s for write (%d)\r\n", fname, fresult);
        send_uart(msg);
        return 0;
    }
    if (iv_hex[0] != '\0') {
        uint8_t iv_bytes[16];
        if (hexstr_to_bytes(iv_hex, iv_bytes, 16) == 16) {
            fresult = f_write(&fil, iv_bytes, 16, &bw);
            if (fresult != FR_OK || bw != 16) {
                char msg[100];
                snprintf(msg, sizeof(msg), "ERROR: Failed to write IV (%d)\r\n", fresult);
                send_uart(msg);
                f_close(&fil);
                return 0;
            }
        } else {
            send_uart("ERROR: Invalid IV hex data\r\n");
            f_close(&fil);
            return 0;
        }
    }
    file_opened = 1;
    return 1;
}
 // kiem tra hash va ghi du lieu vao file
static int write_chunk_to_file(const uint8_t *data, uint16_t len, const uint8_t *sha256) {
    if (!file_opened) {
        send_uart("ERROR: File not opened\r\n");
        return 0;
    }
    // Xác thuc SHA256 cho khoi du lieu
    if (!verify_sha256(data, len, sha256)) {
        send_uart("ERROR: Chunk SHA256 verification failed\r\n");
        return 0;
    }
    fresult = f_write(&fil, data, len, &bw);
    if (fresult != FR_OK || bw != len) {
        char msg[100];
        snprintf(msg, sizeof(msg), "ERROR: Failed to write file (%d)\r\n", fresult);
        send_uart(msg);
        return 0;
    }
    received_file_size += len;
    return 1;
}

static void close_file(void) {
    if (file_opened) {
        f_close(&fil);
        file_opened = 0;
    }
    send_uart("OK: File saved\r\n");
    received_file_size = 0;
    expected_file_size = 0;
    memset(filename, 0, MAX_FILENAME_LEN);
    memset(aes_key_hex, 0, sizeof(aes_key_hex));
    memset(aes_key_bin, 0, sizeof(aes_key_bin));
    memset(iv_hex, 0, sizeof(iv_hex));
}

static void read_file(const char *fname) {
    FIL file;
    fresult = f_open(&file, fname, FA_READ);
    if (fresult != FR_OK) {
        char msg[100];
        snprintf(msg, sizeof(msg), "ERROR: Failed to open file %s (%d)\r\n", fname, fresult);
        send_uart(msg);
        return;
    }
    uint8_t iv_bytes[16];
    fresult = f_read(&file, iv_bytes, 16, &br);
    if (fresult != FR_OK || br != 16) {
        char msg[100];
        snprintf(msg, sizeof(msg), "ERROR: Failed to read IV from file %s\r\n", fname);
        send_uart(msg);
        f_close(&file);
        return;
    }
    char iv_hex_buffer[33];
    for (uint8_t i = 0; i < 16; i++) {
        snprintf(iv_hex_buffer + i*2, sizeof(iv_hex_buffer) - i*2, "%02x", iv_bytes[i]);
    }
    char iv_msg[50];
    snprintf(iv_msg, sizeof(iv_msg), "IV:%s\r\n", iv_hex_buffer);
    send_uart(iv_msg);
    uint8_t buffer[CHUNK_SIZE];
    uint32_t total_bytes_sent = 0;
    while (1) {
        fresult = f_read(&file, buffer, CHUNK_SIZE, &br);
        if (fresult != FR_OK || br == 0) break;
        char hex_buffer[CHUNK_SIZE * 2 + 1];
        for (uint16_t i = 0; i < br; i++) {
            snprintf(hex_buffer + i*2, sizeof(hex_buffer) - i*2, "%02x", buffer[i]);
        }
        hex_buffer[br * 2] = '\0';
        char hex_msg[CHUNK_SIZE * 2 + 3];
        snprintf(hex_msg, sizeof(hex_msg), "%s\r\n", hex_buffer);
        send_uart(hex_msg);
        total_bytes_sent += br;
    }
    f_close(&file);
    char msg[100];
    snprintf(msg, sizeof(msg), "OK: File read completed, sent %lu bytes\r\n", total_bytes_sent);
    send_uart(msg);
}

static void process_command(char *cmd) {
    int len = strlen(cmd);
    while (len > 0 && (cmd[len-1] == '\r' || cmd[len-1] == '\n')) {
        cmd[len-1] = '\0';
        len--;
    }
    char msg[256];
     if (strncmp(cmd, "LOGIN:", 6) == 0) {
        char *encrypted_hash = cmd + 6;
			
        // Ð?c m?t kh?u t? Flash
        char stored_password[64];
        read_string_from_flash(stored_password, sizeof(stored_password));
        if (strlen(stored_password) == 0) {
            send_uart("ERROR: No password stored\r\n");
            return;
        }
				
        // Tính bam SHA256 c?a m?t kh?u luu tr?
        char computed_hex[65];
        computelogin_sha256(stored_password, computed_hex);

        // So sánh
        if (strcmp(encrypted_hash, computed_hex) == 0) {
            
            send_uart("LOGIN_OK\r\n");
        } else {
            send_uart("LOGIN_FAIL\r\n");
        }
    }else if (strncmp(cmd, "SEND_START:", 11) == 0) {
        char *p = cmd + 11;
        char *tok_file = strtok(p, ":");
        char *tok_size = strtok(NULL, ":");
        char *tok_iv = strtok(NULL, ":");
        if (!tok_file || !tok_size || !tok_iv) {
            send_uart("ERROR: Invalid SEND_START format\r\n");
            return;
        }
        strncpy(filename, tok_file, MAX_FILENAME_LEN - 1);
        filename[MAX_FILENAME_LEN - 1] = '\0';
        expected_file_size = strtoul(tok_size, NULL, 10);
        strncpy(iv_hex, tok_iv, 32);
        iv_hex[32] = '\0';
        received_file_size = 0;
        if (!open_file_for_write(filename)) {
            return;
        }
        send_uart("OK: Ready to receive file chunks\r\n");
    } else if (strncmp(cmd, "SEND_CHUNK:", 11) == 0) {
        char *p = cmd + 11;
        char *hex_data = strtok(p, ":");
        char *tok_sha256 = strtok(NULL, ":");
        if (!hex_data || !tok_sha256) {
            send_uart("ERROR: Invalid SEND_CHUNK format\r\n");
            return;
        }
        uint8_t chunk_data[CHUNK_SIZE];
        int chunk_len = hexstr_to_bytes(hex_data, chunk_data, CHUNK_SIZE);
        if (chunk_len <= 0) {
            send_uart("ERROR: Invalid chunk hex data\r\n");
            return;
        }
        uint8_t chunk_sha256[SHA256_LENGTH];
        if (hexstr_to_bytes(tok_sha256, chunk_sha256, SHA256_LENGTH) != SHA256_LENGTH) {
            send_uart("ERROR: Invalid chunk SHA256 hex data\r\n");
            return;
        }
        if (!write_chunk_to_file(chunk_data, chunk_len, chunk_sha256)) {
            return;
        }
        send_uart("OK: Chunk written\r\n");
    } else if (strcmp(cmd, "SEND_END") == 0) {
        close_file();
    } else if (strcmp(cmd, "LIST") == 0) {
        DIR dir;
        FILINFO fno;
        fresult = f_opendir(&dir, "/");
        if (fresult == FR_OK) {
            while (1) {
                fresult = f_readdir(&dir, &fno);
                if (fresult != FR_OK || fno.fname[0] == 0) break;
                if (!(fno.fattrib & AM_DIR)) {
                    char msg[100];
                    snprintf(msg, sizeof(msg), "%s\r\n", fno.fname);
                    send_uart(msg);
                }
            }
            f_closedir(&dir);
        } else {
            send_uart("ERROR: Failed to open directory\r\n");
        }
    } else if (strncmp(cmd, "READ:", 5) == 0) {
        char *p = cmd + 5;
        char *tok_file = strtok(p, ":");
        if (!tok_file) {
            send_uart("ERROR: Invalid READ format\r\n");
            return;
        }
        read_file(tok_file);
    } 
		 else {
        send_uart("ERROR: Unknown command\r\n");
    }

	} 


/* USER CODE END 0 */

/**
 * @brief  The application entry point.
 * @retval int
 */
int main(void) {
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_FATFS_Init();
    MX_USART1_UART_Init();
    MX_SPI1_Init();
    HAL_Delay(500);
    send_uart("STM32 Initialized\r\n");
    generate_key_from_uid();
	/*
	if (!is_string_stored()) {
        // Ghi chu?i "admin/antoanhtn" vào flash
	const char *str = "antoanhtn";
        write_string_to_flash(str);

      
    } else {
        send_uart("OK: String already stored in flash\r\n");
    }
	*/
    fresult = f_mount(&fs, "", 1);
    if (fresult != FR_OK) {
        send_uart("ERROR: Cannot mount SD card\r\n");
    } else {
        send_uart("SD card mounted successfully\r\n");
        HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0|GPIO_PIN_2, GPIO_PIN_SET);
        HAL_Delay(1000);
        HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0|GPIO_PIN_2, GPIO_PIN_RESET);
    }
    uart_rx_buffer_clear();
    while (1) {
        uint8_t ch;
        if (HAL_UART_Receive(&huart1, &ch, 1, 10) == HAL_OK) {
            if (ch == '\r' || ch == '\n') {
                if (uart_rx_index > 0) {
                    uart_rx_buffer[uart_rx_index] = 0;
                    process_command(uart_rx_buffer);
                    uart_rx_buffer_clear();
                }
            } else {
                if (uart_rx_index < UART_RX_BUFFER_SIZE - 1) {
                    uart_rx_buffer[uart_rx_index++] = ch;
                } else {
                    uart_rx_buffer_clear();
                    send_uart("ERROR: Command too long\r\n");
                }
            }
        }
    }
}

/**
 * @brief System Clock Configuration
 * @retval None
 */
void SystemClock_Config(void) {
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
    RCC_OscInitStruct.HSEState = RCC_HSE_ON;
    RCC_OscInitStruct.HSEPredivValue = RCC_HSE_PREDIV_DIV1;
    RCC_OscInitStruct.HSIState = RCC_HSI_ON;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
    RCC_OscInitStruct.PLL.PLLMUL = RCC_PLL_MUL9;
    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
        Error_Handler();
    }
    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                                |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK) {
        Error_Handler();
    }
}

/**
 * @brief SPI1 Initialization Function
 * @retval None
 */
static void MX_SPI1_Init(void) {
    hspi1.Instance = SPI1;
    hspi1.Init.Mode = SPI_MODE_MASTER;
    hspi1.Init.Direction = SPI_DIRECTION_2LINES;
    hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
    hspi1.Init.CLKPolarity = SPI_POLARITY_LOW;
    hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;
    hspi1.Init.NSS = SPI_NSS_SOFT;
    hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_256;
    hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
    hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
    hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
    hspi1.Init.CRCPolynomial = 10;
    if (HAL_SPI_Init(&hspi1) != HAL_OK) {
        Error_Handler();
    }
}

/**
 * @brief USART1 Initialization Function
 * @retval None
 */
static void MX_USART1_UART_Init(void) {
    huart1.Instance = USART1;
    huart1.Init.BaudRate = 115200;
    huart1.Init.WordLength = UART_WORDLENGTH_8B;
    huart1.Init.StopBits = UART_STOPBITS_1;
    huart1.Init.Parity = UART_PARITY_NONE;
    huart1.Init.Mode = UART_MODE_TX_RX;
    huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart1.Init.OverSampling = UART_OVERSAMPLING_16;
    if (HAL_UART_Init(&huart1) != HAL_OK) {
        Error_Handler();
    }
}

/**
 * @brief GPIO Initialization Function
 * @retval None
 */
static void MX_GPIO_Init(void) {
    GPIO_InitTypeDef GPIO_InitStruct = {0};
    __HAL_RCC_GPIOD_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    HAL_GPIO_WritePin(GPIOA, GPIO_PIN_4, GPIO_PIN_RESET);
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0|GPIO_PIN_2, GPIO_PIN_RESET);
    GPIO_InitStruct.Pin = GPIO_PIN_4;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
    GPIO_InitStruct.Pin = GPIO_PIN_0|GPIO_PIN_2;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);
}

/**
 * @brief  This function is executed in case of error occurrence.
 * @retval None
 */
void Error_Handler(void) {
    __disable_irq();
    while (1) {
    }
}

#ifdef  USE_FULL_ASSERT
/**
 * @brief  Reports the name of the source file and the source line number
 *         where the assert_param error has occurred.
 * @param  file: pointer to the source file name
 * @param  line: assert_param error line source number
 * @retval None
 */
void assert_failed(uint8_t *file, uint32_t line) {
}
#endif /* USE_FULL_ASSERT */