#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <archive.h>
#include <archive_entry.h>
#include <sys/wait.h>
#include <sys/mman.h>

#define MAX_FILENAME 512
#define PROGRESS_BAR_WIDTH 50

static int archive_copy_data(struct archive* in, struct archive* out) {
    const void* buf;
    size_t size;
    off_t offset;
    int res = ARCHIVE_OK;

    while (res == ARCHIVE_OK) {
        res = archive_read_data_block(in, &buf, &size, &offset);
        if (res == ARCHIVE_OK) {
            res = archive_write_data_block(out, buf, size, offset);
        }
    }
    return (res == ARCHIVE_EOF) ? ARCHIVE_OK : res;
}
char support_formats[8][8] = {"zip", "tar", "tar.gz", "tar.xz", "xz", "gz", "7z", "tar.7z"};
void display_progress_bar(const char *filename, int progress);
void process_file(const char *filename, int write_fd, int *progress);
char* create_unique_dir(const char *basename);
int unzip(const char *zipfile, int *progress);
int untar(const char *tarfile, int *progress);
int untar_gz(const char *targzfile, int *progress);
int untar_xz(const char *tar_xzfile, int *progress);
int unxz(const char *xzfile, int *progress);
int ungz(const char *gzfile, int *progress);
int un7z(const char *filename, int *progress);
int untar7z(const char *filename, int *progress);
const char* get_file_format(const char *filename);

void display_progress_bar(const char *filename, int progress) {
    printf("\r%s: [", filename);
    int pos = (progress * PROGRESS_BAR_WIDTH) / 100;
    for (int i = 0; i < PROGRESS_BAR_WIDTH; ++i) {
        if (i < pos) {
            printf("=");
        } else if (i == pos) {
            printf(">");
        } else {
            printf(" ");
        }
    }
    printf("] %d%%", progress);
    fflush(stdout);
}

void process_file(const char *filename, int write_fd, int *progress) {
    const char *file_format = get_file_format(filename);
    
    if (file_format == NULL) {
        dprintf(write_fd, "文件不存在: %s\n", filename);
        *progress = 100;
        close(write_fd);
        exit(EXIT_FAILURE);
    }
    
    int result = -1;
    if (strcmp(file_format, "zip") == 0) {
        result = unzip(filename, progress);
    } else if (strcmp(file_format, "tar.gz") == 0) {
        result = untar_gz(filename, progress);
    } else if (strcmp(file_format, "tar.xz") == 0) {
        result = untar_xz(filename, progress);
    } else if (strcmp(file_format, "xz") == 0) {
        result = unxz(filename, progress);
    } else if (strcmp(file_format, "gz") == 0) {
        result = ungz(filename, progress);
    } else if (strcmp(file_format, "7z") == 0) {
        result = un7z(filename, progress);
    } else if (strcmp(file_format, "tar") == 0) {
        result = untar(filename, progress);
    } else {
        dprintf(write_fd, "不支持的文件格式: %s\n", file_format);
        *progress = 100;
        close(write_fd);
        exit(EXIT_FAILURE);
    }

    if (result != 0) {
        dprintf(write_fd, "解压 %s 失败\n", filename);
        *progress = 100;
        exit(EXIT_FAILURE);
    }

    *progress = 100;
    close(write_fd);
    exit(EXIT_SUCCESS);
}

char* create_unique_dir(const char* filename) {
    const char* file_format = get_file_format(filename);
    if (!file_format || strcmp(file_format, "unknown") == 0) {
        fprintf(stderr, "未知或不支持的文件格式\n");
        return NULL;
    }

    char* dirname = (char*)malloc(MAX_FILENAME);
    if (!dirname) {
        //perror("malloc");
        return NULL;
    }

    snprintf(dirname, MAX_FILENAME, "%s", filename);
    size_t len = strlen(dirname);

    if (strcmp(file_format, "tar.gz") == 0) {
        if (len > 7 && strcmp(&dirname[len-7], ".tar.gz") == 0) {
            dirname[len-7] = '\0';
        }
    } else if (strcmp(file_format, "tar.xz") == 0) {
        if (len > 7 && strcmp(&dirname[len-7], ".tar.xz") == 0) {
            dirname[len-7] = '\0';
        }
    } else if (strcmp(file_format, "gz") == 0) {
        if (len > 3 && strcmp(&dirname[len-3], ".gz") == 0) {
            dirname[len-3] = '\0';
        }
    } else if (strcmp(file_format, "xz") == 0) {
        if (len > 3 && strcmp(&dirname[len-3], ".xz") == 0) {
            dirname[len-3] = '\0';
        }
    } else if (strcmp(file_format, "zip") == 0) {
        if (len > 4 && strcmp(&dirname[len-4], ".zip") == 0) {
            dirname[len-4] = '\0';
        }
    } else if (strcmp(file_format, "7z") == 0) {
        if (len > 3 && strcmp(&dirname[len-3], ".7z") == 0) {
            dirname[len-3] = '\0';
        }
    } else if (strcmp(file_format, "tar") == 0) {
        if (len > 4 && strcmp(&dirname[len-4], ".tar") == 0) {
            dirname[len-4] = '\0';
        }
    }
    
    int append_num = 0;
    char unique_dirname[MAX_FILENAME];
    while (1) {
        if (append_num == 0) {
            snprintf(unique_dirname, MAX_FILENAME, "%s", dirname);
        } else {
            snprintf(unique_dirname, MAX_FILENAME, "%s_%d", dirname, append_num);
        }

        if (mkdir(unique_dirname, 0755) == 0) {
            break;
        } else if (errno == EEXIST) {
            append_num++;
        } else {
            //perror("mkdir");
            free(dirname);
            return NULL;
        }
    }
    
    free(dirname);
    return strdup(unique_dirname);
}

int unzip(const char *zipfile, int *progress) {
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    int flags;
    int r;

    flags = ARCHIVE_EXTRACT_TIME;

    a = archive_read_new();
    archive_read_support_format_zip(a);
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    if ((r = archive_read_open_filename(a, zipfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", zipfile, archive_error_string(a));
        return -1;
    }

    char *dirname = create_unique_dir(zipfile);
    if (!dirname) {
        archive_read_close(a);
        archive_read_free(a);
        return -1;
    }

    int total_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        total_files++;
        archive_read_data_skip(a);
    }

    archive_read_close(a);
    archive_read_free(a);

    a = archive_read_new();
    archive_read_support_format_zip(a);
    if ((r = archive_read_open_filename(a, zipfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", zipfile, archive_error_string(a));
        return -1;
    }

    int processed_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *currentFile = archive_entry_pathname(entry);
        char newFilePath[MAX_FILENAME];
        snprintf(newFilePath, MAX_FILENAME, "%s/%s", dirname, currentFile);
        archive_entry_set_pathname(entry, newFilePath);
        //printf("正在解压: %s\n", currentFile);
        archive_write_header(ext, entry);
        archive_copy_data(a, ext);
        archive_write_finish_entry(ext);
        
        processed_files++;
        *progress = (processed_files * 100) / total_files;
    }

    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);

    return 0;
}

int untar(const char *tarfile, int *progress) {
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    int flags;
    int r;

    flags = ARCHIVE_EXTRACT_TIME;

    a = archive_read_new();
    archive_read_support_format_tar(a);
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    if ((r = archive_read_open_filename(a, tarfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", tarfile, archive_error_string(a));
        return -1;
    }

    char *dirname = create_unique_dir(tarfile);
    if (!dirname) {
        archive_read_close(a);
        archive_read_free(a);
        return -1;
    }

    int total_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        total_files++;
        archive_read_data_skip(a);
    }

    archive_read_close(a);
    archive_read_free(a);

    a = archive_read_new();
    archive_read_support_format_tar(a);
    if ((r = archive_read_open_filename(a, tarfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", tarfile, archive_error_string(a));
        return -1;
    }

    int processed_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *currentFile = archive_entry_pathname(entry);
        char newFilePath[MAX_FILENAME];
        snprintf(newFilePath, MAX_FILENAME, "%s/%s", dirname, currentFile);
        archive_entry_set_pathname(entry, newFilePath);
        //printf("正在解压: %s\n", currentFile);
        archive_write_header(ext, entry);
        archive_copy_data(a, ext);
        archive_write_finish_entry(ext);
        
        processed_files++;
        *progress = (processed_files * 100) / total_files;
    }

    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);

    return 0;
}

int untar_gz(const char *targzfile, int *progress) {
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    int flags;
    int r;

    flags = ARCHIVE_EXTRACT_TIME;

    a = archive_read_new();
    archive_read_support_filter_gzip(a);
    archive_read_support_format_tar(a);
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    if ((r = archive_read_open_filename(a, targzfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", targzfile, archive_error_string(a));
        return -1;
    }

    char *dirname = create_unique_dir(targzfile);
    if (!dirname) {
        archive_read_close(a);
        archive_read_free(a);
        return -1;
    }

    int total_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        total_files++;
        archive_read_data_skip(a);
    }

    archive_read_close(a);
    archive_read_free(a);

    a = archive_read_new();
    archive_read_support_filter_gzip(a);
    archive_read_support_format_tar(a);
    if ((r = archive_read_open_filename(a, targzfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", targzfile, archive_error_string(a));
        return -1;
    }
    
    int processed_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *currentFile = archive_entry_pathname(entry);
        char newFilePath[MAX_FILENAME];
        snprintf(newFilePath, MAX_FILENAME, "%s/%s", dirname, currentFile);
        archive_entry_set_pathname(entry, newFilePath);
        //printf("正在解压: %s\n", currentFile);
        archive_write_header(ext, entry);
        archive_copy_data(a, ext);
        archive_write_finish_entry(ext);
        
        processed_files++;
        *progress = (processed_files * 100) / total_files;
    }

    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);

    return 0;
}

int untar_xz(const char *tar_xzfile, int *progress) {
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    int flags;
    int r;

    flags = ARCHIVE_EXTRACT_TIME;

    a = archive_read_new();
    archive_read_support_filter_xz(a);
    archive_read_support_format_tar(a);
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    if ((r = archive_read_open_filename(a, tar_xzfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", tar_xzfile, archive_error_string(a));
        return -1;
    }

    char *dirname = create_unique_dir(tar_xzfile);
    if (!dirname) {
        archive_read_close(a);
        archive_read_free(a);
        return -1;
    }

    int total_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        total_files++;
        archive_read_data_skip(a);
    }

    archive_read_close(a);
    archive_read_free(a);

    a = archive_read_new();
    archive_read_support_filter_xz(a);
    archive_read_support_format_tar(a);
    if ((r = archive_read_open_filename(a, tar_xzfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", tar_xzfile, archive_error_string(a));
        return -1;
    }
    
    int processed_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *currentFile = archive_entry_pathname(entry);
        char newFilePath[MAX_FILENAME];
        snprintf(newFilePath, MAX_FILENAME, "%s/%s", dirname, currentFile);
        archive_entry_set_pathname(entry, newFilePath);
        //printf("正在解压: %s\n", currentFile);
        archive_write_header(ext, entry);
        archive_copy_data(a, ext);
        archive_write_finish_entry(ext);
        
        processed_files++;
        *progress = (processed_files * 100) / total_files;
    }

    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);

    return 0;
}

int unxz(const char *xzfile, int *progress) {
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    int flags;
    int r;

    flags = ARCHIVE_EXTRACT_TIME;

    a = archive_read_new();
    archive_read_support_filter_xz(a);
    archive_read_support_format_raw(a);
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    if ((r = archive_read_open_filename(a, xzfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", xzfile, archive_error_string(a));
        return -1;
    }

    char *dirname = create_unique_dir(xzfile);
    if (!dirname) {
        archive_read_close(a);
        archive_read_free(a);
        return -1;
    }

    int total_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        total_files++;
        archive_read_data_skip(a);
    }

    archive_read_close(a);
    archive_read_free(a);

    a = archive_read_new();
    archive_read_support_filter_xz(a);
    archive_read_support_format_raw(a);
    if ((r = archive_read_open_filename(a, xzfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", xzfile, archive_error_string(a));
        return -1;
    }
    
    int processed_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *currentFile = archive_entry_pathname(entry);
        char newFilePath[MAX_FILENAME];
        snprintf(newFilePath, MAX_FILENAME, "%s/%s", dirname, currentFile);
        archive_entry_set_pathname(entry, newFilePath);
        //printf("正在解压: %s\n", currentFile);
        archive_write_header(ext, entry);
        archive_copy_data(a, ext);
        archive_write_finish_entry(ext);
        
        processed_files++;
        *progress = (processed_files * 100) / total_files;
    }

    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);

    return 0;
}

int ungz(const char *gzfile, int *progress) {
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    int flags;
    int r;

    flags = ARCHIVE_EXTRACT_TIME;

    a = archive_read_new();
    archive_read_support_filter_gzip(a);
    archive_read_support_format_raw(a);
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    if ((r = archive_read_open_filename(a, gzfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", gzfile, archive_error_string(a));
        return -1;
    }

    char *dirname = create_unique_dir(gzfile);
    if (!dirname) {
        archive_read_close(a);
        archive_read_free(a);
        return -1;
    }

    int total_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        total_files++;
        archive_read_data_skip(a);
    }

    archive_read_close(a);
    archive_read_free(a);

    a = archive_read_new();
    archive_read_support_filter_gzip(a);
    archive_read_support_format_raw(a);
    if ((r = archive_read_open_filename(a, gzfile, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", gzfile, archive_error_string(a));
        return -1;
    }
    
    int processed_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *currentFile = archive_entry_pathname(entry);
        char newFilePath[MAX_FILENAME];
        snprintf(newFilePath, MAX_FILENAME, "%s/%s", dirname, currentFile);
        archive_entry_set_pathname(entry, newFilePath);
        //printf("正在解压: %s\n", currentFile);
        archive_write_header(ext, entry);
        archive_copy_data(a, ext);
        archive_write_finish_entry(ext);
        
        processed_files++;
        *progress = (processed_files * 100) / total_files;
    }

    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);

    return 0;
}

int un7z(const char *filename, int *progress) {
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    int flags;
    int r;

    flags = ARCHIVE_EXTRACT_TIME;

    a = archive_read_new();
    archive_read_support_format_7zip(a);
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    if ((r = archive_read_open_filename(a, filename, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", filename, archive_error_string(a));
        return -1;
    }

    char *dirname = create_unique_dir(filename);
    if (!dirname) {
        archive_read_close(a);
        archive_read_free(a);
        return -1;
    }

    int total_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        total_files++;
        archive_read_data_skip(a);
    }

    archive_read_close(a);
    archive_read_free(a);

    a = archive_read_new();
    archive_read_support_format_7zip(a);
    if ((r = archive_read_open_filename(a, filename, 10240))) {
        fprintf(stderr, "无法打开文件 %s: %s\n", filename, archive_error_string(a));
        return -1;
    }
    
    int processed_files = 0;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *currentFile = archive_entry_pathname(entry);
        char newFilePath[MAX_FILENAME];
        snprintf(newFilePath, MAX_FILENAME, "%s/%s", dirname, currentFile);
        archive_entry_set_pathname(entry, newFilePath);
        //printf("正在解压: %s\n", currentFile);
        archive_write_header(ext, entry);
        archive_copy_data(a, ext);
        archive_write_finish_entry(ext);
        
        processed_files++;
        *progress = (processed_files * 100) / total_files;
    }

    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);

    return 0;
}

int untar7z(const char *filename, int *progress) {
    return un7z(filename, progress);
}

const char* get_file_format(const char *filename) {
    unsigned char buffer[512];
    FILE *file = fopen(filename, "rb");
    if (!file) {
        //perror("fopen");
        return NULL;
    }

    if (fread(buffer, 1, sizeof(buffer), file) != sizeof(buffer)) {
        //perror("fread");
        fclose(file);
        return NULL;
    }
    fclose(file);

    if (memcmp(buffer, "\x50\x4B\x03\x04", 4) == 0) {
        return "zip";
    } else if (memcmp(buffer, "\x1F\x8B", 2) == 0) {
        return "tar.gz";
    } else if (memcmp(buffer, "\xFD\x37\x7A\x58\x5A\x00\x00", 7) == 0) {
        return "tar.xz";
    } else if (memcmp(buffer, "\xFD\x37\x7A\x58\x5A", 5) == 0) {
        return "xz";
    } else if (memcmp(buffer, "\x1F\x8B\x08", 3) == 0) {
        return "gz";
    } else if (memcmp(buffer, "\x37\x7A\xBC\xAF\x27\x1C", 6) == 0) {
        return "7z";
    } else if (memcmp(buffer + 257, "ustar", 5) == 0) {
        return "tar";
    } else {
        return "unknown";
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "用法: %s <压缩文件1> <压缩文件2> ...\n", argv[0]);
        return EXIT_FAILURE;
    }

    size_t shm_size = sizeof(int) * argc;
    int *progress = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (progress == MAP_FAILED) {
        //perror("mmap");
        return EXIT_FAILURE;
    }
    memset(progress, 0, shm_size);

    for (int i = 1; i < argc; ++i) {
        pid_t pid = fork();
        if (pid < 0) {
            //perror("fork");
            return EXIT_FAILURE;
        } else if (pid == 0) {
            process_file(argv[i], STDOUT_FILENO, &progress[i]);
            fflush(stdout);
            exit(EXIT_SUCCESS);
        }
    }

    int all_done;
    do {
        all_done = 1;
        for (int i = 1; i < argc; ++i) {
            if (progress[i] < 100) {
                all_done = 0;
            }
            display_progress_bar(argv[i], progress[i]);
            fflush(stdout);
        }
        usleep(100000);
    } while (!all_done);

    for (int i = 1; i < argc; ++i) {
        wait(NULL);
    }

    munmap(progress, shm_size);
    printf("\n所有文件处理完毕\n");
    return EXIT_SUCCESS;
}
