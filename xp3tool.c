// kirikiri xp3 v1 unpacker/packer (currently only supporting morenatsu ver3.5 enc/dec, windows and linux)

#if defined(_MSC_VER)
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>
#include <errno.h>
#include <assert.h>

#include <zlib.h>

#ifdef __GNUC__
// Assume GCC-compatible and linux
#include <fcntl.h>
#include <linux/limits.h> // PATH_MAX

#define WFOPEN(file_name, mode) fopen((char *)file_name, (char *)mode)
#define SWPRINTF swprintf

// This is actually standard, not GCC-specific
#define PACKED_STRUCT_BEGIN \
    _Pragma("pack(push, 1)")
#define PACKED_STRUCT_END \
    _Pragma("pack(pop)")

#elif defined(_MSC_VER)
// MSVC C compiler
#include <io.h>
#include <fcntl.h>

#define PATH_MAX _MAX_PATH

#define WFOPEN(file_name, mode) _wfopen(file_name, mode)
#define SWPRINTF _snwprintf

#define PACKED_STRUCT_BEGIN \
    __pragma(pack(push, 1))
#define PACKED_STRUCT_END \
    __pragma(pack(pop))

#endif

#ifdef _WIN32
#include <direct.h>  // _wmkdir
#include <windows.h> // win32 stuff

#define PATH_SEPARATOR L"\\"
#define PATH_SEPARATOR_WCHAR L'\\'
#define PATH_SEPARATOR_CHAR '\\'
#define MKDIR _wmkdir

#else

#define PATH_SEPARATOR L"/"
#define PATH_SEPARATOR_WCHAR L'/'
#define PATH_SEPARATOR_CHAR '/'
#define MKDIR(name) mkdir(name, 0755)

#endif

// NOTE: MSVC allows a trailing comma before __VA_ARGS__, Clang and GCC do not.
// The following syntax works out for all those compilers.
#define LOG(fmt, ...) printf("[xp3tool] - " fmt "\n", ##__VA_ARGS__)
#define ERR(fmt, ...) fprintf(stderr, "[xp3tool] - " fmt "\n", ##__VA_ARGS__)

#if defined(__GNUC__)
#define WLOG(fmt, ...) wprintf(L"[xp3tool] - " fmt L"\n", ##__VA_ARGS__);
#define WERR(fmt, ...) fwprintf(stderr, L"[xp3tool] - " fmt L"\n", ##__VA_ARGS__);
#elif defined(_MSC_VER)
/* Set stdout to file mode UTF-16 text, then reset to UTF-8 mode */
#define WLOG(fmt, ...)                                 \
    (void)_setmode(_fileno(stdout), _O_U16TEXT);       \
    wprintf(L"[xp3tool] - " fmt L"\n", ##__VA_ARGS__); \
    (void)_setmode(_fileno(stdout), _O_TEXT);

#define WERR(fmt, ...)                                 \
    (void)_setmode(_fileno(stderr), _O_U16TEXT);       \
    wprintf(L"[xp3tool] - " fmt L"\n", ##__VA_ARGS__); \
    (void)_setmode(_fileno(stderr), _O_TEXT);
#endif

#define CHUNK_SIZE 4096
#define XP3_ENCRYPTED_FLAG (1 << 31) // 0x80000000
#define XP3_SEGMENT_SIZE 28

const uint8_t XP3_MAGIC[] = { 'X', 'P', '3', '\r', '\n', 0x20, 0x0A, 0x1A, 0x8B, 0x67, 0x01 };

PACKED_STRUCT_BEGIN
typedef struct xp3_header_t
{
    uint8_t magic[11];
    uint64_t index_offset;
} xp3_header;
PACKED_STRUCT_END

PACKED_STRUCT_BEGIN
typedef struct xp3_index_t
{
    uint64_t compressed_size;
    uint64_t decompressed_size;
} xp3_index;
PACKED_STRUCT_END

PACKED_STRUCT_BEGIN
typedef struct xp3_entry_t
{
    char pad0[0x04];
    uint64_t entry_len;
    char pad1[0x04];
    uint64_t info_length;
    uint32_t encrypted;
    uint64_t decompressed_size;
    uint64_t compressed_size;
    uint16_t file_name_len;
} xp3_entry;
PACKED_STRUCT_END

PACKED_STRUCT_BEGIN
typedef struct xp3_segment_t
{
    uint32_t compressed;
    uint64_t offset;
    uint64_t decompressed_size;
    uint64_t compressed_size;
} xp3_segment;
PACKED_STRUCT_END

static FILE* g_file;

static const char* get_filename(const char* path)
{
    const char* last_separator = strrchr(path, PATH_SEPARATOR_CHAR);

    if (last_separator != NULL)
    {
        return last_separator + 1;
    }

    return path;
}

static const wchar_t* wget_filename(const wchar_t* path)
{
    const wchar_t* last_separator = wcsrchr(path, PATH_SEPARATOR_WCHAR);

    if (last_separator != NULL)
    {
        return last_separator + 1;
    }

    return path;
}

static bool file_exists(const wchar_t* path)
{
#ifdef _WIN32
    DWORD attrib = GetFileAttributesW(path);
    return (attrib != INVALID_FILE_ATTRIBUTES) && !(attrib & FILE_ATTRIBUTE_DIRECTORY);
#else
    size_t len = wcslen(path) + 1;
    char narrow_path[PATH_MAX] = { 0 };
    wcstombs(narrow_path, path, len);

    struct stat st;
    return (stat(narrow_path, &st) == 0) && S_ISREG(st.st_mode);
#endif
}

static bool dir_exists(const wchar_t* dir_path)
{
#ifdef _WIN32
    DWORD attrib = GetFileAttributesW(dir_path);
    return (attrib != INVALID_FILE_ATTRIBUTES) && (attrib & FILE_ATTRIBUTE_DIRECTORY);
#else
    size_t len = wcslen(dir_path) + 1;
    char narrow_path[PATH_MAX] = { 0 };
    wcstombs(narrow_path, dir_path, len);

    struct stat st;
    return (stat(narrow_path, &st) == 0) && S_ISDIR(st.st_mode);
#endif
}

static void create_dir_if_not_exists(const wchar_t* dir_path)
{
    if (!dir_exists(dir_path))
    {
        // The directory does not exist. Create it
#if defined(_MSC_VER)
        if (MKDIR(dir_path) != 0)
#elif defined(__GNUC__)
        size_t len = wcslen(dir_path) + 1;
        char narrow_path[PATH_MAX] = { 0 };
        wcstombs(narrow_path, dir_path, len);

        if (MKDIR(narrow_path) != 0)
#endif
        {
            WERR(L"Failed to create directory: %ls. errno: %d", dir_path, errno);
        }
    }
}

static void create_dirs_if_not_exist(const wchar_t* dir_path)
{
    wchar_t current_path[PATH_MAX] = { 0 };
    const wchar_t* p = dir_path;

    while (*p)
    {
        if (*p == L'/' || *p == L'\\')
        {
            wcsncpy(current_path, dir_path, p - dir_path);
            if (!dir_exists(current_path))
            {
#ifdef _WIN32
                if (MKDIR(current_path) != 0)
#elif defined(__GNUC__)
                size_t len = wcslen(dir_path) + 1;
                char narrow_path[PATH_MAX] = { 0 };
                wcstombs(narrow_path, dir_path, len);
                if (MKDIR(narrow_path) != 0)
#endif
                {
                    WERR(L"Failed to create directory: %ls. errno: %d", current_path, errno);
                    return; // If creating an intermediate directory fails, return early
                }
            }
        }
        ++p;
    }

    // Create the final directory
    if (!dir_exists(dir_path))
    {
#ifdef _WIN32
        if (MKDIR(dir_path) != 0)
#elif defined(__GNUC__)
        size_t len = wcslen(dir_path) + 1;
        char narrow_path[PATH_MAX] = { 0 };
        wcstombs(narrow_path, dir_path, len);
        if (MKDIR(narrow_path) != 0)
#endif
        {
            WERR(L"Failed to create directory: %ls. errno: %d", dir_path, errno);
        }
    }
}

static void get_dir_name_and_file_name(const wchar_t* path, wchar_t* directory, wchar_t* file_name)
{
    // Find the last occurrence of the dir separator
    const wchar_t* last_separator = wcsrchr(path, '/');

    // Extract the directory and file names
    if (last_separator != NULL)
    {
        // Calculate the length of the dir name
        size_t dir_length = last_separator - path; // Remove the separator

        wmemcpy(directory, path, dir_length);
        directory[dir_length] = L'\0'; // Null-terminate the directory name

        // Copy the file name
        wcscpy(file_name, last_separator + 1);
    }
    else
    {
        // XXX: this is probably unnecessary for this use-case, idk
        // No directory separator found, the entire path is the file name
        wcscpy(directory, L"");
        wcscpy(file_name, path);
    }
}

static size_t peek(FILE* stream, void* buffer, size_t n)
{
    size_t bytes_read = fread(buffer, 1, n, stream);
    fseek(stream, -((long)bytes_read), SEEK_CUR);
    return bytes_read;
}

static size_t peek_at(FILE* stream, void* buffer, size_t n, uint64_t offset)
{
    long current_pos = ftell(stream);

    fseek(stream, (long)offset, SEEK_SET);
    size_t bytes_read = fread(buffer, 1, n, stream);
    fseek(stream, current_pos, SEEK_SET);

    return bytes_read;
}

static size_t get_file_size(FILE* file)
{
    size_t file_size;

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    return file_size;
}

static bool is_xp3()
{
    unsigned char magic[sizeof(XP3_MAGIC)];

    peek(g_file, magic, sizeof(magic));
    if (memcmp(magic, XP3_MAGIC, sizeof(XP3_MAGIC)))
    {
        return false;
    }

    return true;
}

inline static void read_header(xp3_header* hdr)
{
    peek(g_file, hdr, sizeof(xp3_header));
}

inline static void read_index(xp3_index* idx, uint64_t offset)
{
    peek_at(g_file, idx, sizeof(xp3_index), offset);
}

inline static void parse_entry(xp3_entry* entry, uint8_t* buf, uint64_t offset)
{
    memcpy(entry, buf + offset, sizeof(xp3_entry));
}

inline static void parse_segment(xp3_segment* segment, uint8_t* buf, uint64_t offset)
{
    memcpy(segment, buf + offset, sizeof(xp3_segment));
}

static void pack(const char* path)
{
    // TODO
}

// Decompresses zlib data from a buffer to out_file_path
static void decompress_buffer_to_file(const unsigned char* buffer, size_t size, wchar_t* out_file_path)
{
    // Create an output file for writing decompressed data
    FILE* output_file = WFOPEN(out_file_path, L"wb");
    if (output_file == NULL)
    {
        ERR("Failed to open output file for writing.");
        exit(1);
    }

    // Allocate buffer for decompressed data
    unsigned char out_buf[CHUNK_SIZE];

    // Init zlib stream
    z_stream zstream;
    zstream.zalloc = Z_NULL;
    zstream.zfree = Z_NULL;
    zstream.opaque = Z_NULL;

    if (inflateInit(&zstream) != Z_OK)
    {
        ERR("Failed to initialize zlib.");
        exit(1);
    }

    // Set input data
    zstream.avail_in = (uInt)size;
    zstream.next_in = (Bytef*)buffer;

    int ret;

    do
    {
        zstream.avail_out = CHUNK_SIZE;
        zstream.next_out = (Bytef*)out_buf;

        ret = inflate(&zstream, Z_NO_FLUSH);
        if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
        {
            ERR("Failed to decompress data: %s", zstream.msg);
            inflateEnd(&zstream);
            fclose(output_file);

            // XXX: Don't exit yet, some zlib compressed files have probably been tampered with
            // to prevent extraction. (mostly .txt files)
            // exit(1);
        }

        size_t have = CHUNK_SIZE - zstream.avail_out;

        fwrite(out_buf, sizeof(char), have, output_file);

    } while (zstream.avail_out == 0);

    inflateEnd(&zstream);
    fclose(output_file);
}

// Decompresses zlib data to out_file_path
static void decompress_offset_to_path(uint64_t data_offset, wchar_t* out_file_path)
{
    // Create an output file for writing decompressed data
    FILE* output_file = WFOPEN(out_file_path, L"wb");
    if (output_file == NULL)
    {
        ERR("Failed to open output file for writing.");
        exit(1);
    }

    fseek(g_file, (long)data_offset, SEEK_SET);

    // Allocate buffers for compressed and decompressed data
    unsigned char in_buf[CHUNK_SIZE];
    unsigned char out_buf[CHUNK_SIZE];

    // Init zlib stream
    z_stream zstream;
    zstream.zalloc = Z_NULL;
    zstream.zfree = Z_NULL;
    zstream.opaque = Z_NULL;
    zstream.avail_in = 0;
    zstream.next_in = Z_NULL;
    if (inflateInit(&zstream) != Z_OK)
    {
        ERR("Failed to initialize zlib.");
        exit(1);
    }

    // Read and decompress data in chunks
    int ret;
    do
    {
        zstream.avail_in = (uInt)fread(in_buf, 1, CHUNK_SIZE, g_file);
        if (zstream.avail_in == 0)
            break;

        zstream.next_in = (Bytef*)in_buf;

        do
        {
            zstream.avail_out = CHUNK_SIZE;
            zstream.next_out = (Bytef*)out_buf;

            ret = inflate(&zstream, Z_NO_FLUSH);
            if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR)
            {
                ERR("Failed to decompress data: %s", zstream.msg);
                inflateEnd(&zstream);
                fclose(output_file);
                exit(1);
            }

            size_t have = CHUNK_SIZE - zstream.avail_out;

            fwrite(out_buf, sizeof(char), have, output_file);

        } while (zstream.avail_out == 0);
    } while (ret != Z_STREAM_END);

    inflateEnd(&zstream);
    fclose(output_file);

    fseek(g_file, 0, SEEK_SET);
}

static int unpack(const wchar_t* file_path, const wchar_t* output_dir)
{
    if (!file_exists(file_path))
    {
        ERR("The specified input file does not exist.");
        return 1;
    }

    if (dir_exists(output_dir))
    {
        WERR(L"Output directory \"%ls\" already exists.", output_dir);
        return 1;
    }

#if defined(__GNUC__)
    size_t len = wcslen(output_dir) + 1;
    char narrow_path[PATH_MAX] = { 0 };
    wcstombs(narrow_path, output_dir, len);
    (void)MKDIR(narrow_path);
#else
    (void)MKDIR(output_dir);
#endif


    g_file = WFOPEN(file_path, L"rb");
    if (g_file == (void*)-1)
    {
        WERR(L"Could not open %ls for reading.", file_path);
        return 1;
    }

    // Check file magic
    if (!is_xp3())
    {
        WERR(L"%ls is not a valid XP3 file.", file_path);
        return 1;
    }

    size_t file_size = get_file_size(g_file);

    // Read XP3 header
    xp3_header hdr = { 0 };
    read_header(&hdr);
    assert(hdr.index_offset < file_size);

    // Read XP3 index
    xp3_index idx = { 0 };
    read_index(&idx, hdr.index_offset);

    LOG("Decompressing index data...");

    wchar_t out_file_path[PATH_MAX] = { 0 };
    SWPRINTF(out_file_path, PATH_MAX, L"%ls.idx", file_path);

    // Decompress XP3 index to a file
    decompress_offset_to_path(hdr.index_offset + sizeof(xp3_index) + 1, out_file_path);

    // Read XP3 index file into a buffer
    FILE* idx_file = WFOPEN(out_file_path, L"rb");
    size_t idx_file_size = get_file_size(idx_file);

    uint8_t* idx_data = malloc(idx_file_size);
    if (idx_data == NULL)
    {
        ERR("Could not allocate buffer for XP3 index data.");
        return 1;
    }

    size_t bytes_read = fread(idx_data, sizeof(char), idx_file_size, idx_file);
    fclose(idx_file);

    assert(bytes_read == idx_file_size);

    // 50MB buffer to store extracted files
    uint8_t* file_buf = malloc(50 * 1024 * 1024);

    static bool first = true;

    for (int i = 0; i < idx_file_size;)
    {
        xp3_entry entry = { 0 };
        parse_entry(&entry, idx_data, i);

        i += sizeof(xp3_entry);

        wchar_t file_path[2048] = { 0 };
        for (int j = 0; j < entry.file_name_len; j++)
        {
            memcpy(&file_path[j], idx_data + i, sizeof(wchar_t));

            i += sizeof(wchar_t);
        }

        i += sizeof("segm") - 1; // Skip 'segm'

        uint64_t segments_num;
        memcpy(&segments_num, idx_data + i, sizeof(segments_num));
        segments_num /= XP3_SEGMENT_SIZE; // 28 bytes per segment
        i += sizeof(uint64_t);

        WLOG(L"Extracting %ls", file_path);

        //if (!first && !(entry.encrypted & XP3_ENCRYPTED_FLAG))
        //{
        //    WERR(L"%ls is encrypted!", file_path);
        //    return 1;
        //}

        int file_compressed_size = 0;
        int segment_start_offset = i;
        xp3_segment segments[128] = { 0 };
        for (int j = 0; j < segments_num; j++)
        {
            // XXX: Skip the first iteration for Morenatsu XP3, as the filename contains
            // invalid path name chars. I assume this is on purpose
            if (first)
            {
                i += sizeof(xp3_segment);

                first = false;
                goto skip_first;
            }

            parse_segment(&segments[j], idx_data + segment_start_offset, j * sizeof(xp3_segment));
            // i += sizeof(xp3_segment);

            wchar_t file_dir_path[PATH_MAX] = { 0 };
            wchar_t out_file[PATH_MAX] = { 0 };
            get_dir_name_and_file_name(file_path, file_dir_path, out_file);

            wchar_t out_dir[PATH_MAX] = { 0 };
            SWPRINTF(out_dir, PATH_MAX, L"%ls" PATH_SEPARATOR L"%ls", output_dir, file_dir_path);

            create_dirs_if_not_exist(out_dir);

            wchar_t out_file_path[PATH_MAX] = { 0 };
            SWPRINTF(out_file_path, PATH_MAX, L"%ls" PATH_SEPARATOR L"%ls", out_dir, out_file);

            fseek(g_file, (long)segments[j].offset, SEEK_SET);

            fread(file_buf, sizeof(uint8_t), segments[j].decompressed_size, g_file);

            FILE* extracted_file = NULL;
            if (segments_num > 1)
            {
                extracted_file = WFOPEN(out_file_path, L"ab");
            }
            else
            {
                extracted_file = WFOPEN(out_file_path, L"wb");
            }

            if (extracted_file == NULL)
            {
                WERR(L"Cannot open %ls for writing.", file_path);
                return 1;
            }

            fwrite(file_buf, sizeof(uint8_t), segments[j].decompressed_size, extracted_file);
            fclose(extracted_file);

            file_compressed_size += segments[j].compressed_size;

            fseek(g_file, 0, SEEK_SET);

            // FIXME: this is a workaround. we should be able to determine
            // if it's compressed or not beforehand
            if (entry.compressed_size != entry.decompressed_size && j == (segments_num - 1))
            {
                decompress_buffer_to_file(file_buf, file_compressed_size, out_file_path);
            }
        }

        i += sizeof(xp3_segment) * segments_num;

    skip_first:
        i += sizeof("adlr") - 1; // Skip 'adlr'
        i += sizeof(uint64_t);   // 04 00 00 00 00 00 00 00 00

        uint32_t adler;
        memcpy(&adler, idx_data + i, sizeof(adler));

        i += sizeof(uint32_t); // Account for adler chk
    }

    free(file_buf);
    free(idx_data);

    fclose(g_file);
    return 0;
}

int main(int argc, char* argv[])
{
    // XXX: idk if the following is actually needed and when
    setlocale(LC_ALL, "");

    wchar_t input_file[PATH_MAX];
    wchar_t output_dir[PATH_MAX] = L"output";

    if (argc == 1)
    {
        WERR(L"Usage: %hs -i input_file [-o output_dir]", get_filename(argv[0]));
        return 1;
    }

    // Parse command-line args
    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-h") == 0)
        {
            // Print usage and exit
            WERR(L"Usage: %hs -i input_file [-o output_dir]", get_filename(argv[0]));
            return 0;
        }
        else if (strcmp(argv[i], "-i") == 0)
        {
            // Set input file
            if (i + 1 < argc)
            {
                size_t len = mbstowcs(NULL, argv[i + 1], 0);
                if (len != (size_t)-1)
                {
                    mbstowcs(input_file, argv[i + 1], len + 1);
                    i++; // Skip the next arg (input file)
                }
                else
                {
                    WERR(L"Error: Failed to convert input file to wide characters");
                    return 1;
                }
            }
            else
            {
                WERR(L"Error: No input file specified after -i");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-o") == 0)
        {
            // Set output dir
            if (i + 1 < argc)
            {
                size_t len = mbstowcs(NULL, argv[i + 1], 0);
                if (len != (size_t)-1)
                {
                    mbstowcs(output_dir, argv[i + 1], len + 1);
                    i++; // Skip the next arg (output dir)
                }
                else
                {
                    WERR(L"Error: Failed to convert output dir to wide characters");
                    return 1;
                }
            }
            else
            {
                WERR(L"Error: No output dir specified after -o");
                return 1;
            }
        }
        else
        {
            WERR(L"Error: Unknown option %hs", argv[i]);
            return 1;
        }
    }

    if (input_file == NULL)
    {
        WERR(L"Error: Input file not specified. Use -h for usage.");
        return 1;
    }

    int res = unpack(input_file, output_dir);

    return res;
}
