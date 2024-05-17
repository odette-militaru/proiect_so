#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

#define SNAPSHOT_FILE "snapshot_"

void checkAndIsolate(const char *fullPath, const char *izolated_space_dir) {
    struct stat statbuf;
    if (stat(fullPath, &statbuf) != 0) return; // Verifică existența fișierului/directorului

    if (S_ISREG(statbuf.st_mode)) { // Verifică dacă este un fișier
        char command[2048];
        snprintf(command, sizeof(command), "./verify_for_malicious.sh '%s' '%s'", fullPath, izolated_space_dir);
        system(command);
    }
}


void metasave(const char *path, FILE *snapshot_file, const char *izolated_space_dir) {
    DIR *dir = opendir(path);
    struct dirent *entry;
    struct stat statbuf;
    char fullPath[1024];
    char lastAccessTime[20];
    char lastModTime[20];
    char perm[11];

    if (!dir) {
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(fullPath, sizeof(fullPath), "%s/%s", path, entry->d_name);

        // Aplică verificarea și izolarea
        checkAndIsolate(fullPath, izolated_space_dir);

        if (stat(fullPath, &statbuf) == -1) {
            continue;
        }

        strftime(lastAccessTime, sizeof(lastAccessTime), "%Y-%m-%d %H:%M:%S", localtime(&statbuf.st_atime));
        strftime(lastModTime, sizeof(lastModTime), "%Y-%m-%d %H:%M:%S", localtime(&statbuf.st_mtime));
        snprintf(perm, sizeof(perm), "%c%c%c%c%c%c%c%c%c%c",
                 (S_ISDIR(statbuf.st_mode)) ? 'd' : '-',
                 (statbuf.st_mode & S_IRUSR) ? 'r' : '-',
                 (statbuf.st_mode & S_IWUSR) ? 'w' : '-',
                 (statbuf.st_mode & S_IXUSR) ? 'x' : '-',
                 (statbuf.st_mode & S_IRGRP) ? 'r' : '-',
                 (statbuf.st_mode & S_IWGRP) ? 'w' : '-',
                 (statbuf.st_mode & S_IXGRP) ? 'x' : '-',
                 (statbuf.st_mode & S_IROTH) ? 'r' : '-',
                 (statbuf.st_mode & S_IWOTH) ? 'w' : '-',
                 (statbuf.st_mode & S_IXOTH) ? 'x' : '-');

        fprintf(snapshot_file, "Path: %s\nInode Number: %ld\nSize: %ld bytes\nPermissions: %s\nLast Access: %s\nLast Modified: %s\n\n",
                fullPath, statbuf.st_ino, statbuf.st_size, perm, lastAccessTime, lastModTime);
    }

    closedir(dir);
}

void create_snapshot(const char *basePath, const char *output_dir, const char *izolated_space_dir) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/%s%s.txt", output_dir, SNAPSHOT_FILE, strrchr(basePath, '/') ? strrchr(basePath, '/') + 1 : basePath);

    FILE *snapshot_file = fopen(filename, "w");
    if (!snapshot_file) {
        exit(EXIT_FAILURE);
    }

    metasave(basePath, snapshot_file, izolated_space_dir);
    fclose(snapshot_file);
    printf("Snapshot for Directory %s created successfully.\n", basePath);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        return EXIT_FAILURE;
    }

    char *output_dir = NULL;
    char *izolated_space_dir = NULL;
    int dir_start = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
            dir_start = i + 1;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            izolated_space_dir = argv[++i];
            dir_start = i + 1;
        }
    }

    for (int i = dir_start; i < argc; i++) {
        pid_t pid = fork();
        if (pid == 0) { // Child process
            create_snapshot(argv[i], output_dir, izolated_space_dir);
            exit(EXIT_SUCCESS);
        }
    }

    int status = 0;
    pid_t pid;
    while ((pid = wait(&status)) != -1) {
        if (WIFEXITED(status)) {
            printf("Child Process terminated with PID %d and exit code %d.\n", pid, WEXITSTATUS(status));
        }
    }

    return EXIT_SUCCESS;
}
