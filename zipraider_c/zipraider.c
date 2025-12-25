/**
 * ZipRaider-C - High Performance ZIP Password Cracker
 * Author: Aryan Giri
 * Compile: gcc -o zipraider zipraider.c -lzip -lcrypto -pthread -O3 -march=native
 * Usage: ./zipraider -f encrypted.zip -w rockyou.txt
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <zip.h>
#include <errno.h>
#include <dirent.h>

#define VERSION "2.1"
#define MAX_PASSWORD_LEN 256
#define MAX_PATH_LEN 4096
#define WORKER_THREADS 4
#define PROGRESS_INTERVAL 100000

// Character sets
static const char *charsets[] = {
    "abcdefghijklmnopqrstuvwxyz",                      // lower
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",                      // upper
    "0123456789",                                      // digits
    "!@#$%^&*()-_=+[]{}|;:,.<>?",                      // symbols
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", // alphanum
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?", // all
    "0123456789abcdef",                                // hex
    "01"                                               // binary
};

typedef enum {
    CHARSET_LOWER,
    CHARSET_UPPER,
    CHARSET_DIGITS,
    CHARSET_SYMBOLS,
    CHARSET_ALPHANUM,
    CHARSET_ALL,
    CHARSET_HEX,
    CHARSET_BINARY,
    CHARSET_COUNT
} charset_type;

typedef struct {
    char zipfile[MAX_PATH_LEN];
    char wordlist[MAX_PATH_LEN];
    char output_dir[MAX_PATH_LEN];
    char charset[256];
    int min_len;
    int max_len;
    int mode;  // 0=dictionary, 1=bruteforce
    int charset_id;
    int threads;
    int verbose;
} config_t;

typedef struct {
    unsigned long long attempts;
    int found;
    char password[MAX_PASSWORD_LEN];
    double start_time;
    pthread_mutex_t mutex;
} stats_t;

typedef struct {
    config_t *config;
    stats_t *stats;
    int thread_id;
} worker_data_t;

// Function prototypes
void print_banner(void);
void print_usage(void);
int test_password_brute(const char *zipfile, const char *password);
int test_password_dict(const char *zipfile, const char *password);
void dictionary_attack(config_t *config, stats_t *stats);
void brute_force_attack(config_t *config, stats_t *stats);
void *brute_force_worker(void *arg);
void analyze_zip(const char *zipfile);
int extract_files(const char *zipfile, const char *password, const char *output_dir);
unsigned long long total_combinations(const char *charset, int min_len, int max_len);
void generate_password(char *buffer, unsigned long long index, const char *charset, int length);
int file_exists(const char *path);
void progress_report(stats_t *stats);
int create_directory_recursive(const char *path);
int verify_password(const char *zipfile, const char *password);

// Global variables for thread control
volatile int stop_workers = 0;

int main(int argc, char *argv[]) {
    config_t config = {0};
    stats_t stats = {0};
    
    // Default values
    strcpy(config.charset, charsets[CHARSET_ALPHANUM]);
    config.min_len = 1;
    config.max_len = 6;
    config.mode = 0;  // dictionary mode
    config.threads = WORKER_THREADS;
    config.verbose = 0;
    strcpy(config.output_dir, "extracted");
    config.charset_id = CHARSET_ALPHANUM;
    
    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "f:w:o:m:c:l:L:t:vh")) != -1) {
        switch (opt) {
            case 'f':
                strncpy(config.zipfile, optarg, MAX_PATH_LEN - 1);
                config.zipfile[MAX_PATH_LEN - 1] = '\0';
                break;
            case 'w':
                strncpy(config.wordlist, optarg, MAX_PATH_LEN - 1);
                config.wordlist[MAX_PATH_LEN - 1] = '\0';
                config.mode = 0;  // dictionary mode
                break;
            case 'o':
                strncpy(config.output_dir, optarg, MAX_PATH_LEN - 1);
                config.output_dir[MAX_PATH_LEN - 1] = '\0';
                break;
            case 'm':
                if (strcmp(optarg, "dict") == 0) config.mode = 0;
                else if (strcmp(optarg, "brute") == 0) config.mode = 1;
                break;
            case 'c':
                if (strcmp(optarg, "lower") == 0) {
                    strcpy(config.charset, charsets[CHARSET_LOWER]);
                    config.charset_id = CHARSET_LOWER;
                } else if (strcmp(optarg, "upper") == 0) {
                    strcpy(config.charset, charsets[CHARSET_UPPER]);
                    config.charset_id = CHARSET_UPPER;
                } else if (strcmp(optarg, "digits") == 0) {
                    strcpy(config.charset, charsets[CHARSET_DIGITS]);
                    config.charset_id = CHARSET_DIGITS;
                } else if (strcmp(optarg, "symbols") == 0) {
                    strcpy(config.charset, charsets[CHARSET_SYMBOLS]);
                    config.charset_id = CHARSET_SYMBOLS;
                } else if (strcmp(optarg, "alphanum") == 0) {
                    strcpy(config.charset, charsets[CHARSET_ALPHANUM]);
                    config.charset_id = CHARSET_ALPHANUM;
                } else if (strcmp(optarg, "all") == 0) {
                    strcpy(config.charset, charsets[CHARSET_ALL]);
                    config.charset_id = CHARSET_ALL;
                } else if (strcmp(optarg, "hex") == 0) {
                    strcpy(config.charset, charsets[CHARSET_HEX]);
                    config.charset_id = CHARSET_HEX;
                } else if (strcmp(optarg, "binary") == 0) {
                    strcpy(config.charset, charsets[CHARSET_BINARY]);
                    config.charset_id = CHARSET_BINARY;
                }
                break;
            case 'l':
                config.min_len = atoi(optarg);
                if (config.min_len < 1) config.min_len = 1;
                break;
            case 'L':
                config.max_len = atoi(optarg);
                if (config.max_len < config.min_len) config.max_len = config.min_len;
                break;
            case 't':
                config.threads = atoi(optarg);
                if (config.threads < 1) config.threads = 1;
                if (config.threads > 32) config.threads = 32;
                break;
            case 'v':
                config.verbose = 1;
                break;
            case 'h':
                print_usage();
                return 0;
            default:
                print_usage();
                return 1;
        }
    }
    
    print_banner();
    
    // Check if zip file exists
    if (config.zipfile[0] == '\0') {
        fprintf(stderr, "Error: No ZIP file specified\n");
        print_usage();
        return 1;
    }
    
    if (!file_exists(config.zipfile)) {
        fprintf(stderr, "Error: ZIP file '%s' not found\n", config.zipfile);
        return 1;
    }
    
    // Analyze ZIP file
    printf("[*] Analyzing ZIP file: %s\n", config.zipfile);
    analyze_zip(config.zipfile);
    
    // Initialize stats
    stats.start_time = (double)clock() / CLOCKS_PER_SEC;
    stats.attempts = 0;
    stats.found = 0;
    if (pthread_mutex_init(&stats.mutex, NULL) != 0) {
        fprintf(stderr, "Error: Mutex initialization failed\n");
        return 1;
    }
    
    // Start attack
    printf("\n[*] Starting attack...\n");
    if (config.mode == 0) {  // Dictionary attack
        if (config.wordlist[0] == '\0') {
            // Try default wordlists
            const char *default_wordlists[] = {
                "/usr/share/wordlists/rockyou.txt",
                "rockyou.txt",
                "wordlist.txt",
                NULL
            };
            
            int found = 0;
            for (int i = 0; default_wordlists[i] != NULL; i++) {
                if (file_exists(default_wordlists[i])) {
                    strcpy(config.wordlist, default_wordlists[i]);
                    found = 1;
                    break;
                }
            }
            
            if (!found) {
                fprintf(stderr, "Error: No wordlist specified and default wordlists not found\n");
                printf("You can download rockyou.txt from:\n");
                printf("https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt\n");
                return 1;
            }
        }
        
        if (!file_exists(config.wordlist)) {
            fprintf(stderr, "Error: Wordlist '%s' not found\n", config.wordlist);
            return 1;
        }
        
        printf("[*] Using wordlist: %s\n", config.wordlist);
        dictionary_attack(&config, &stats);
    } else {  // Brute force attack
        printf("[*] Brute force mode\n");
        const char *charset_names[] = {
            "lowercase",
            "uppercase",
            "digits",
            "symbols",
            "alphanumeric",
            "all",
            "hex",
            "binary"
        };
        
        printf("[*] Charset: %s\n", charset_names[config.charset_id]);
        printf("[*] Length: %d to %d characters\n", config.min_len, config.max_len);
        
        unsigned long long total = total_combinations(config.charset, config.min_len, config.max_len);
        printf("[*] Total combinations: %llu\n", total);
        printf("[*] Using %d threads\n", config.threads);
        
        stop_workers = 0;
        brute_force_attack(&config, &stats);
    }
    
    // Report results
    double elapsed = ((double)clock() / CLOCKS_PER_SEC) - stats.start_time;
    printf("\n========================================\n");
    printf("CRACKING RESULTS\n");
    printf("========================================\n");
    
    if (stats.found) {
        // Verify the password actually works before declaring victory
        if (verify_password(config.zipfile, stats.password)) {
            printf("[+] PASSWORD FOUND: %s\n", stats.password);
            printf("[+] Attempts: %llu\n", stats.attempts);
            printf("[+] Time: %.2f seconds\n", elapsed);
            if (elapsed > 0) {
                printf("[+] Speed: %.0f pwd/sec\n", stats.attempts / elapsed);
            }
            
            // Extract files
            if (extract_files(config.zipfile, stats.password, config.output_dir)) {
                printf("[+] Files extracted to: %s/\n", config.output_dir);
            } else {
                printf("[!] Password found but extraction failed (wrong password?)\n");
            }
        } else {
            // False positive - the password doesn't actually work
            printf("[-] PASSWORD NOT FOUND (false positive detected)\n");
            printf("[+] Attempts: %llu\n", stats.attempts);
            printf("[+] Time: %.2f seconds\n", elapsed);
            if (elapsed > 0) {
                printf("[+] Speed: %.0f pwd/sec\n", stats.attempts / elapsed);
            }
        }
    } else {
        printf("[-] PASSWORD NOT FOUND\n");
        printf("[+] Attempts: %llu\n", stats.attempts);
        printf("[+] Time: %.2f seconds\n", elapsed);
        if (elapsed > 0) {
            printf("[+] Speed: %.0f pwd/sec\n", stats.attempts / elapsed);
        }
    }
    
    printf("========================================\n");
    printf("ZipRaider-C v%s by Aryan Giri\n", VERSION);
    printf("========================================\n");
    
    pthread_mutex_destroy(&stats.mutex);
    return 0;
}

void print_banner(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                     ZipRaider-C v%s                       ║\n", VERSION);
    printf("║              High Performance ZIP Cracker                    ║\n");
    printf("║                    Author: Aryan Giri                        ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void print_usage(void) {
    printf("Usage: ./zipraider -f <zipfile> [OPTIONS]\n\n");
    printf("Options:\n");
    printf("  -f <file>     ZIP file to crack (required)\n");
    printf("  -w <file>     Wordlist for dictionary attack\n");
    printf("  -o <dir>      Output directory for extracted files\n");
    printf("  -m <mode>     Attack mode: dict or brute\n");
    printf("  -c <charset>  Character set: lower, upper, digits, symbols,\n");
    printf("                alphanum, all, hex, binary\n");
    printf("  -l <min>      Minimum password length (brute force)\n");
    printf("  -L <max>      Maximum password length (brute force)\n");
    printf("  -t <threads>  Number of threads (default: 4)\n");
    printf("  -v            Verbose output\n");
    printf("  -h            Show this help\n\n");
    
    printf("Examples:\n");
    printf("  ./zipraider -f encrypted.zip -w rockyou.txt\n");
    printf("  ./zipraider -f flag.zip -m brute -c digits -l 4 -L 6\n");
    printf("  ./zipraider -f secret.zip -m brute -c lower -l 3 -L 5 -t 8\n");
}

int test_password_brute(const char *zipfile, const char *password) {
    int err = 0;
    struct zip *za = zip_open(zipfile, 0, &err);
    if (!za) {
        return 0;
    }
    
    // Get number of entries
    int num_entries = zip_get_num_entries(za, 0);
    if (num_entries <= 0) {
        zip_close(za);
        return 0;
    }
    
    // Try each file with the password
    for (int i = 0; i < num_entries; i++) {
        // Try to open the file with the password
        struct zip_file *zf = zip_fopen_index_encrypted(za, i, 0, password);
        if (zf) {
            // Try to read a small amount of data to verify password
            char buffer[1];
            int bytes = zip_fread(zf, buffer, 1);
            zip_fclose(zf);
            
            if (bytes >= 0) {
                // Successfully read data - password works
                zip_close(za);
                return 1;
            }
        }
    }
    
    zip_close(za);
    return 0;
}

int test_password_dict(const char *zipfile, const char *password) {
    return test_password_brute(zipfile, password);
}

int verify_password(const char *zipfile, const char *password) {
    // More thorough verification by actually extracting a file
    int err = 0;
    struct zip *za = zip_open(zipfile, 0, &err);
    if (!za) {
        return 0;
    }
    
    int num_entries = zip_get_num_entries(za, 0);
    if (num_entries <= 0) {
        zip_close(za);
        return 0;
    }
    
    // Try to extract first file to a temporary location
    int success = 0;
    for (int i = 0; i < num_entries; i++) {
        struct zip_file *zf = zip_fopen_index_encrypted(za, i, 0, password);
        if (zf) {
            // Create a test extraction
            char temp_filename[MAX_PATH_LEN];
            snprintf(temp_filename, sizeof(temp_filename), "/tmp/zipraider_test_%d_%d.tmp", getpid(), i);
            
            FILE *temp_file = fopen(temp_filename, "wb");
            if (temp_file) {
                char buffer[1024];
                int bytes_read;
                int total_bytes = 0;
                
                // Try to read some data
                while ((bytes_read = zip_fread(zf, buffer, sizeof(buffer))) > 0) {
                    total_bytes += bytes_read;
                    if (total_bytes > 1024) {
                        // Read enough to verify
                        break;
                    }
                }
                
                fclose(temp_file);
                remove(temp_filename);  // Clean up
                
                if (bytes_read >= 0) {  // No error during read
                    success = 1;
                    zip_fclose(zf);
                    break;
                }
            }
            zip_fclose(zf);
        }
    }
    
    zip_close(za);
    return success;
}

void dictionary_attack(config_t *config, stats_t *stats) {
    FILE *fp = fopen(config->wordlist, "r");
    if (!fp) {
        fprintf(stderr, "Error opening wordlist: %s\n", config->wordlist);
        return;
    }
    
    char password[MAX_PASSWORD_LEN];
    unsigned long long count = 0;
    
    printf("[*] Starting dictionary attack...\n");
    
    while (fgets(password, sizeof(password), fp) && !stop_workers) {
        // Remove newline
        size_t len = strlen(password);
        if (len > 0 && password[len - 1] == '\n') {
            password[len - 1] = '\0';
        }
        
        // Skip empty lines
        if (strlen(password) == 0) {
            continue;
        }
        
        count++;
        
        pthread_mutex_lock(&stats->mutex);
        stats->attempts++;
        if (stats->attempts % PROGRESS_INTERVAL == 0) {
            progress_report(stats);
        }
        pthread_mutex_unlock(&stats->mutex);
        
        // Test password
        if (test_password_dict(config->zipfile, password)) {
            // Double-check with verification
            if (verify_password(config->zipfile, password)) {
                pthread_mutex_lock(&stats->mutex);
                stats->found = 1;
                strncpy(stats->password, password, MAX_PASSWORD_LEN - 1);
                stats->password[MAX_PASSWORD_LEN - 1] = '\0';
                stop_workers = 1;
                pthread_mutex_unlock(&stats->mutex);
                break;
            }
        }
    }
    
    fclose(fp);
}

void brute_force_attack(config_t *config, stats_t *stats) {
    pthread_t threads[config->threads];
    worker_data_t worker_data[config->threads];
    
    // Create worker threads
    for (int i = 0; i < config->threads; i++) {
        worker_data[i].config = config;
        worker_data[i].stats = stats;
        worker_data[i].thread_id = i;
        if (pthread_create(&threads[i], NULL, brute_force_worker, &worker_data[i]) != 0) {
            fprintf(stderr, "Error creating thread %d\n", i);
            // Continue with fewer threads
            config->threads = i;
            break;
        }
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < config->threads; i++) {
        pthread_join(threads[i], NULL);
    }
}

void *brute_force_worker(void *arg) {
    worker_data_t *data = (worker_data_t *)arg;
    config_t *config = data->config;
    stats_t *stats = data->stats;
    int thread_id = data->thread_id;
    
    char password[MAX_PASSWORD_LEN];
    int charset_len = strlen(config->charset);
    
    // Divide work among threads
    for (int length = config->min_len; length <= config->max_len; length++) {
        // Calculate total combinations for this length
        unsigned long long total_for_length = 1;
        for (int i = 0; i < length; i++) {
            if (total_for_length > ULLONG_MAX / charset_len) {
                // Overflow protection
                total_for_length = ULLONG_MAX;
                break;
            }
            total_for_length *= charset_len;
        }
        
        // Each thread handles a portion of the combinations
        for (unsigned long long idx = thread_id; idx < total_for_length && !stop_workers; idx += config->threads) {
            // Check if password already found
            pthread_mutex_lock(&stats->mutex);
            if (stats->found) {
                pthread_mutex_unlock(&stats->mutex);
                return NULL;
            }
            
            // Update stats
            stats->attempts++;
            if (stats->attempts % PROGRESS_INTERVAL == 0 && config->verbose) {
                progress_report(stats);
            }
            pthread_mutex_unlock(&stats->mutex);
            
            // Generate password
            generate_password(password, idx, config->charset, length);
            
            // Test password (quick test first)
            if (test_password_brute(config->zipfile, password)) {
                // Double-check with verification
                if (verify_password(config->zipfile, password)) {
                    pthread_mutex_lock(&stats->mutex);
                    if (!stats->found) {
                        stats->found = 1;
                        strncpy(stats->password, password, MAX_PASSWORD_LEN - 1);
                        stats->password[MAX_PASSWORD_LEN - 1] = '\0';
                        stop_workers = 1;
                    }
                    pthread_mutex_unlock(&stats->mutex);
                    return NULL;
                }
            }
        }
    }
    
    return NULL;
}

void analyze_zip(const char *zipfile) {
    int err = 0;
    struct zip *za = zip_open(zipfile, 0, &err);
    if (!za) {
        printf("[-] Error opening ZIP file: %s\n", zip_strerror(za));
        return;
    }
    
    int num_entries = zip_get_num_entries(za, 0);
    printf("[*] Files in archive: %d\n", num_entries);
    
    // Check if encrypted
    int encrypted_files = 0;
    for (int i = 0; i < num_entries; i++) {
        struct zip_stat st;
        if (zip_stat_index(za, i, 0, &st) == 0) {
            const char *name = zip_get_name(za, i, 0);
            if (name) {
                if (st.encryption_method != 0 || (st.valid & ZIP_STAT_ENCRYPTION_METHOD)) {
                    printf("    - %s (ENCRYPTED)\n", name);
                    encrypted_files++;
                } else {
                    printf("    - %s\n", name);
                }
            }
        }
    }
    
    if (encrypted_files == 0) {
        printf("[-] WARNING: No encrypted files found in archive!\n");
        printf("[-] This file may not be password protected.\n");
    } else {
        printf("[*] Found %d encrypted file(s)\n", encrypted_files);
    }
    
    zip_close(za);
}

int extract_files(const char *zipfile, const char *password, const char *output_dir) {
    int err = 0;
    struct zip *za = zip_open(zipfile, 0, &err);
    if (!za) {
        fprintf(stderr, "Error opening zip file for extraction\n");
        return 0;
    }
    
    // Create output directory
    if (!create_directory_recursive(output_dir)) {
        fprintf(stderr, "Error creating output directory\n");
        zip_close(za);
        return 0;
    }
    
    int num_entries = zip_get_num_entries(za, 0);
    int extracted = 0;
    int success = 0;
    
    for (int i = 0; i < num_entries; i++) {
        struct zip_file *zf = zip_fopen_index_encrypted(za, i, 0, password);
        if (!zf) {
            continue; // Skip files we can't open
        }
        
        const char *name = zip_get_name(za, i, 0);
        if (name) {
            char output_path[MAX_PATH_LEN];
            snprintf(output_path, sizeof(output_path), "%s/%s", output_dir, name);
            
            // Create parent directories if needed
            char *last_slash = strrchr(output_path, '/');
            if (last_slash) {
                *last_slash = '\0';
                create_directory_recursive(output_path);
                *last_slash = '/';
            }
            
            FILE *out = fopen(output_path, "wb");
            if (out) {
                char buffer[8192];
                int bytes;
                int file_success = 1;
                while ((bytes = zip_fread(zf, buffer, sizeof(buffer))) > 0) {
                    if (fwrite(buffer, 1, bytes, out) != bytes) {
                        file_success = 0;
                        break;
                    }
                }
                fclose(out);
                
                if (file_success && bytes >= 0) {  // bytes >= 0 means no error
                    extracted++;
                    success = 1;
                    if (extracted <= 5) { // Show first 5 files
                        printf("[+] Extracted: %s\n", name);
                    }
                } else {
                    // Extraction failed - wrong password
                    remove(output_path);  // Clean up partial file
                    success = 0;
                    break;
                }
            }
        }
        
        zip_fclose(zf);
        if (!success) break;
    }
    
    if (extracted > 5) {
        printf("[+] Extracted %d files total\n", extracted);
    }
    
    zip_close(za);
    return success;
}

unsigned long long total_combinations(const char *charset, int min_len, int max_len) {
    int charset_len = strlen(charset);
    unsigned long long total = 0;
    
    for (int len = min_len; len <= max_len; len++) {
        unsigned long long combos = 1;
        for (int i = 0; i < len; i++) {
            if (combos > ULLONG_MAX / charset_len) {
                combos = ULLONG_MAX;
                break;
            }
            combos *= charset_len;
        }
        
        if (total > ULLONG_MAX - combos) {
            total = ULLONG_MAX;
            break;
        }
        total += combos;
    }
    
    return total;
}

void generate_password(char *buffer, unsigned long long index, const char *charset, int length) {
    int charset_len = strlen(charset);
    unsigned long long temp = index;
    
    for (int i = length - 1; i >= 0; i--) {
        buffer[i] = charset[temp % charset_len];
        temp /= charset_len;
    }
    buffer[length] = '\0';
}

int file_exists(const char *path) {
    FILE *fp = fopen(path, "r");
    if (fp) {
        fclose(fp);
        return 1;
    }
    return 0;
}

void progress_report(stats_t *stats) {
    double elapsed = ((double)clock() / CLOCKS_PER_SEC) - stats->start_time;
    double speed = (elapsed > 0) ? stats->attempts / elapsed : 0;
    printf("[*] Attempts: %llu, Speed: %.0f pwd/sec, Time: %.1fs\n", 
           stats->attempts, speed, elapsed);
}

int create_directory_recursive(const char *path) {
    char tmp[MAX_PATH_LEN];
    char *p = NULL;
    size_t len;
    
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }
    
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    
    return mkdir(tmp, 0755) == 0 || errno == EEXIST;
}
