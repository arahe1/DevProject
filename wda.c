#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <curl/curl.h>

#include "wda_version.h"
#include "wda.h"
#include "frontier_client/frontier.h"
#include "frontier_protocol.h"

#define DEBUG   0
#define DEBUG_MALLOC 0


# if defined(__linux__)
#   define USE_MMAPPED 1
#   include <openssl/md5.h>
# endif

# if defined(__APPLE__)
#   define USE_MMAPPED 0
#   define COMMON_DIGEST_FOR_OPENSSL 1
#   include <CommonCrypto/CommonDigest.h>
# endif
/*
 * Internal data structures
 */

typedef struct {
    size_t ncolumns;    // Number of columns in CSV row
    size_t nelements;   // Number of elements in data array
    char **columns;     // Pointers to columns
//    double data[2];     // The data array
} DataRec;


struct HttpResponse {
    char *memory;       // The buffer from HTTP response
    size_t size;        // The size of the buffer (in bytes)
    size_t allocsize;   // The allocated size of the buffer (in bytes)
    char **rows;        // Array of rows in the buffer
    size_t nrows;       // Number of rows
    size_t idx;         // Current index
    long http_code;     // Status code
    DataRec *dataRecs[0];   // Array of parsed data records. Filled by getTuple calls
    void *state;	// Pointer to frontier state
    unsigned long statelong;// Unsigned Long frontier state
};


static int destroyHttpResponse(HttpResponse *response);
static int initHttpResponse(HttpResponse *response);
static HttpResponse get_response(const char *url, const char *headers[], size_t nheaders, int timeout, int *status);
static inline HttpResponse mget_response(const char *url, const char *urls[], size_t nurls, const char *headers[], size_t nheaders, int timeout, int *status);
static void postHTTP_retry(const char *url, const char *headers[], size_t nheaders, const char *data, size_t length, int timeout, int *status);

static int Debug = 0;

static HttpResponse mget_frontier_response(const char *url, const char *headers[], size_t nheaders, int timeout, int *status); //Frontier Declaration
#define PRINT_ALLOC_ERROR(a)   fprintf(stderr, "Not enough memory (%s returned NULL)" \
            " at %s:%d\n", #a, __FILE__, __LINE__)

# if DEBUG_MALLOC
typedef struct {
    unsigned long size,resident,share,text,lib,data,dt;
} statm_t;

void read_off_memory_status(statm_t *result)
{
    unsigned long dummy;
    const char* statm_path = "/proc/self/statm";

    FILE *f = fopen(statm_path,"r");
    if (!f) {
        perror(statm_path);
        //abort();
    }
    if (7 != fscanf(f,"%ld %ld %ld %ld %ld %ld %ld",
        &result->size,&result->resident,&result->share,&result->text,&result->lib,&result->data,&result->dt))
    {
        perror(statm_path);
        //abort();
    }
    fclose(f);
    fprintf(stderr, "********* Memory: total=%ldkB, resident=%ldkB, shared=%ldkB, text=%ldkB, (data+stack)=%ldkB *********\n\n",
        result->size*4, result->resident*4, result->share*4, result->text*4, result->data*4);
}
# endif

#define MIN(a,b)    ( ((a) <= (b)) ? (a) : (b) )


/*
 * Low level functions to work with LIBCURL globals
 */
int wda_global_init() {
    return curl_global_init(CURL_GLOBAL_ALL);
}

void wda_global_cleanup() {
    curl_global_cleanup();
}

/*
 * Generates a random string of specified size
 */
static char *randStr(char *dst, int size)
{
   static const char text[] = "abcdefghijklmnopqrstuvwxyz"
                              "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "0123456789";
   int i;

   srandom(time(0));

   for (i = 0; i < size; ++i) {
      dst[i] = text[random() % (sizeof text - 1)];
   }
   dst[i] = '\0';
   return dst;
}


/*
 * Calculates MD5 signature for the buffer with a given password, salt string, and optional arguments string.
 */
static char *MD5Signature(const char *pwd, const char *salt, const char *args, const char *buf, size_t length)
{
    int n;
    MD5_CTX c;
    unsigned char digest[16];
    static char out[34];

    MD5_Init(&c);

    MD5_Update(&c, pwd, strlen(pwd));
    MD5_Update(&c, salt, strlen(salt));
    if (args)
        MD5_Update(&c, args, strlen(args));
    MD5_Update(&c, buf, length);

    MD5_Final(digest, &c);

    for (n = 0; n < 16; n++) {
        snprintf(&(out[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }

    return out;
}

/*
 * Returns string buffer with ascii time representation
 */
static char *strtime() {
    time_t tm = time(NULL);
    char *ts = ctime(&tm);
    ts[strlen(ts)-1] = '\0';
    return ts;
}


/*
 *  LibCurl API
 */
static size_t writeMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    HttpResponse *response = (HttpResponse *)userp;

//  fprintf(stderr, "writeMemoryCallback: processed %d bytes\n", realsize);
    size_t newalloc;
    int needalloc;
    size_t newsize = response->size + realsize;
    char *tptr = response->memory;
    for (needalloc = 0, newalloc = response->allocsize; newalloc <= newsize; newalloc *= 2) {
        needalloc = 1;
    }
    if (needalloc) {
# if DEBUG_MALLOC
        fprintf(stderr, "allocate=%d, need %d\n", newalloc, newsize);
# endif
# if USE_MMAPPED
        tptr = (char *)mremap(response->memory, response->allocsize, newalloc, MREMAP_MAYMOVE);
        if (tptr == MAP_FAILED || tptr == 0) {
            /* out of memory! */
            PRINT_ALLOC_ERROR(mremap);
            return 0;
        }
# else
        tptr = (char *)realloc(response->memory, newalloc);
        if (tptr == NULL) {
            /* out of memory! */
            PRINT_ALLOC_ERROR(realloc);
            return 0;
        }
# endif
        response->allocsize = newalloc;
        response->memory = tptr; // If reallocated size, set response->memory to new memory buffer size ptr
    }
# if DEBUG_MALLOC
    if (tptr!=response->memory) {
        fprintf(stderr, "#############writeMemoryCallback: response.memory moved, delta=%ld ", (long)(tptr-response->memory));
        fprintf(stderr, "response.size=%d(+%d)\n", response->size, realsize);
        //fprintf(stderr, "#############writeMemoryCallback: response.memory = %p\n", response->memory);
    }
# endif
    memcpy(&(response->memory[response->size]), contents, realsize);
    response->size += realsize;
    response->memory[response->size] = '\0';
# if 0
    statm_t stat;
    fprintf(stderr, "writeMemoryCallback: processed %d bytes\n", realsize);
    read_off_memory_status(&stat);
# endif
    return realsize;
}


/*
 * External function to return a handle to the HttpResponse
 */
HttpResponse *wda_get_response_handle(const char* url, const char *headers[], size_t nheaders, size_t *length, int *status)
{
    HttpResponse response = get_response(url, headers, nheaders, 0, status);
    *length = response.size;

    HttpResponse *response_cpy = (HttpResponse*)malloc(sizeof(HttpResponse));
    *response_cpy = response;
    return response_cpy;
}

// Given an HttpResponse handle eturn pointer to HttpResponse buffer
void *wda_get_response_buffer(HttpResponse *response)
{
    return (void *)response->memory;
}

// Wrapper for destroyHttpResponse to release buffer memory to system given a HttpResponse handle
void wda_release_response_buffer(HttpResponse *response)
{
    destroyHttpResponse(response); // deallocate the buffer
    free(response);// Need to deallocate the rest of the HttpResponse
}


/*
 * The function communicates with the server using CURL library
 * It returns pointer to the data as return value and passes data size via parameter
 */
void *getHTTP(const char *url, const char *headers[], size_t nheaders, size_t *length, int *status)
{
    HttpResponse response = get_response(url, headers, nheaders, 0, status);

    *length = response.size;                // Return data length
    return (void *)response.memory;         // Return pointer to the buffer
}



/*
 * The function communicates with the server using CURL library
 * It returns pointer to the data as return value and passes data size via parameter
 */
void *getHTTPWithTimeout(const char *url, const char *headers[], size_t nheaders, size_t *length, int timeout, int *status)
{
    HttpResponse response = get_response(url, headers, nheaders, timeout, status);

    *length = response.size;		    // Return data length
    return (void *)response.memory;         // Return pointer to the buffer
}



/*
 * Internal helper
 */

static struct curl_slist *add_headers(const char *headers[], size_t nheaders)
{
    int i;
    struct curl_slist *headerlist = NULL;
    char user_agent[256];
    snprintf(user_agent, 256, "User-Agent: wdaAPI/%s (UID=%d, PID=%d)", WDA_VERSION, getuid(), getpid());
    if (headers) {                                     // Add extra headers if present
        for (i = 0; i < nheaders; i++) {
            if (headers[i])
                headerlist = curl_slist_append(headerlist, headers[i]);
        }
    }
    headerlist = curl_slist_append(headerlist, user_agent);
    return headerlist;
}

/*
 * Internal common function. Calls curl_easy_perform() with the parameters set in the caller.
 * Does mutiple retries if timeout provided in the arguments.
 * Does round-robin selection from the URL list if provided.
 * Now is used for GETs and POSTs
 */
static CURLcode perform_with_timeout(CURL *curl_handle,
            HttpResponse *response,
            const char *url, const char *urls[], size_t nurls,
            const char *headers[], size_t nheaders,
            int timeout, int *status)
{
    CURLcode ret = CURLE_FAILED_INIT;

    time_t t0 = time(NULL);
    time_t t1 = t0;
    int iurl = -1;
    const char *aurl = NULL;
    long http_code = -1;
    char *ca_info, *ca_path, *connect_to;

    srandom(t0);                     // Set seed for a new random sequence

    if (response) {
        initHttpResponse(response);
    }
    aurl = (url!=NULL) ? url : ((urls!=NULL && nurls > 0) ? urls[iurl = random()%nurls] : NULL);
    if (aurl==NULL) {                // Both url and urls are not set
        *status = CURLE_FAILED_INIT; // Set status
        return CURLE_FAILED_INIT;    // Return error
    }

    struct curl_slist *headerlist = add_headers(headers, nheaders);
    // Set extra headers
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headerlist);
    // Set HTTP version
    curl_easy_setopt(curl_handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

    int dt = 0;
    int k = 0;
    do {
        if (response) {
            destroyHttpResponse(response); initHttpResponse(response);
        }
        // Specify the URL for request
        if (Debug >= 1) {   // DEBUG
            fprintf(stderr, "[%s] %s: URL index=%d, URL='%s'\n", strtime(), __func__, iurl, aurl);
        }
        curl_easy_setopt(curl_handle, CURLOPT_URL, aurl);
        if (ca_info = getenv("SSL_CERT_FILE")) {
            if (strlen(ca_info) > 0) {
                curl_easy_setopt(curl_handle, CURLOPT_CAINFO, ca_info);
            } else {
                curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
                fprintf(stderr, "[%s] %s: Warning: CA verification is off. URL='%s'\n", strtime(), __func__, aurl);
            }
        }
        if (ca_path = getenv("SSL_CERT_DIR")) {
            // fprintf(stderr, "[%s] %s: ca_path='%s'\n", strtime(), __func__, ca_path);
            if (strlen(ca_path) > 0) {
                if ( Debug >= 2 ) {
                    fprintf(stderr, "[%s] %s: ****** ca_path='%s'\n", strtime(), __func__, ca_path);
                }
                curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1);
                ret = curl_easy_setopt(curl_handle, CURLOPT_CAPATH, ca_path);
                if (ret != CURLE_OK) {  // Check for errors
                    fprintf(stderr, "%s: curl_easy_perform() failed: %s\n", __func__, curl_easy_strerror(ret));
                } else {
                    if ( Debug >= 2 ) {
                        fprintf(stderr, "%s: curl_easy_perform() CURLOPT_CAPATH: %s\n", __func__, curl_easy_strerror(ret));
                    }
                }
            }
        }
        if (connect_to = getenv("LIBWDA_CONNECTTIMEOUT")) {
            if (strlen(connect_to) > 0) {
                long cto = atol(connect_to);
                curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, cto);
            } else {
                /* complete connection within 30 seconds */
                curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 30L);
            }
        }

        ret = curl_easy_perform(curl_handle);

        *status = ret;
        if (ret != CURLE_OK) {  // Check for errors
            fprintf(stderr, "[%s] %s: curl_easy_perform() failed: '%s'\n", strtime(), __func__, curl_easy_strerror(ret));
            fprintf(stderr, "[%s] %s: URL='%s'\n", strtime(), __func__, aurl);
            fprintf(stderr, "[%s] %s: rc=%d, try=%d, delay=%d, t0=%ld, dt=%ld timeout=%d\n", strtime(), __func__, ret, k, dt, t0, t1-t0, timeout);
            if (response) {
                response->size = response->http_code = 0;
            }
        } else {
            curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
            if (Debug >= 3) {   // DEBUG
                if (response) {
                    fprintf(stderr, "[%s] %s: HTTP status code=%d: '%.*s'...\n", strtime(), __func__, http_code, MIN(strlen(response->memory), 50), response->memory);
                } else {
                    fprintf(stderr, "[%s] %s: HTTP status code=%d\n", strtime(), __func__, http_code);
                }
            }
            http_code = http_code==0 ? 200 : http_code;
            if (http_code == 200 && ret != CURLE_ABORTED_BY_CALLBACK) {
                //Succeeded
                // if (k > 0)
                if (Debug >= 1) {   // DEBUG
                    fprintf(stderr, "[%s] %s: SUCCESS, try=%d, delay=%d, t0=%ld, dt=%ld timeout=%d\n", strtime(), __func__, k, dt, t0, t1-t0, timeout);
                }
                break;
            }
        }
        if (urls!=NULL && nurls > 0) {    // Go to next URL in the list
            iurl = ((iurl < 0) ? random() : iurl+1) % nurls;
            aurl = urls[iurl];
        } else if ((http_code / 100) == 4) {
            // Server error - can't continue
            fprintf(stderr, "[%s] %s: %s\n", strtime(), __func__, "Server error - cannot continue");
            fprintf(stderr, "[%s] %s: rc=%d, try=%d, delay=%d, t0=%ld, dt=%ld timeout=%d\n", strtime(), __func__, ret, k, dt, t0, t1-t0, timeout);
            break;
        } else {
            // sleep and retry
            dt = 1 + ((double)random()/(double)RAND_MAX) * (1 << k++);
            sleep(dt);
            t1 = time(NULL);
        }
    } while ((t1 - t0) < timeout);
    if (Debug >= 2 && (t1 - t0) > timeout) {   // DEBUG
        fprintf(stderr, "[%s] %s: %s\n", strtime(), __func__, "Timeout: gave up...");
        fprintf(stderr, "[%s] %s: rc=%d, try=%d, delay=%d, t0=%ld, dt=%ld timeout=%d\n", strtime(), __func__, ret, k, dt, t0, t1-t0, timeout);
    }

    curl_slist_free_all(headerlist);            // Free the custom headers
    if (response) {
        response->http_code = http_code;        // Store HTTP status code in response if provided
    }
    return ret;                                 // Return curl return code
}

/*
 * Internal common function
 * Main function, does all work using libcurl.
 * If 'url' argument is present uses it as a primary source.
 * If 'urls' argument is present uses it as a backup sources with the first randomly selected and then goes round robin.
 */
static HttpResponse mget_http_response(const char *url, const char *urls[], size_t nurls, const char *headers[], size_t nheaders, int timeout, int *status)
{
    CURL *curl_handle;
    CURLcode ret = CURLE_FAILED_INIT;
    char *dbg = getenv("LIBWDA_DEBUG");
    if (dbg) {
        if (strcmp("0", dbg)==0) {
            Debug = 0;
        } else if (strcmp("2", dbg)==0) {
            Debug = 2;
        } else if (strcmp("3", dbg)==0) {
            Debug = 3;
        } else if (strcmp("4", dbg)==0) {
            Debug = 4;
        } else {
            Debug = 1;
        }
    } else {
        Debug = 0;
    }

    HttpResponse response;

    initHttpResponse(&response);

    ret = curl_global_init(CURL_GLOBAL_ALL);

    if (ret != CURLE_OK) {              // Check for errors
        curl_global_cleanup();
        *status = ret;                  // Return status
        return response;                // Return response structure
    }
    // init the curl session
    curl_handle = curl_easy_init();
    if (curl_handle) {

        /* send all data to this function  */
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, writeMemoryCallback);

        /* we pass our 'response' struct to the callback function */
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&response);

        /* Enable redirection */
        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1);

        ret = perform_with_timeout(curl_handle, &response, url, urls, nurls, headers, nheaders, timeout, status);

        // Cleanup curl stuff
        curl_easy_cleanup(curl_handle);
# if DEBUG
        fprintf(stderr, "mget_http_response: %lu bytes retrieved\n", (long)response.size);
# endif
    }
    // we're done with libcurl, so clean it up
    curl_global_cleanup();

    return response;                        // Return response structure
}



/*
 * Internal common function
 */
static HttpResponse get_csv_file(const char *url, int *status)
{
    HttpResponse response;
    int i, k;

    initHttpResponse(&response);

    FILE *fp = fopen(url, "rb");
//    fprintf(stderr, "Open file '%s'\n", url);

    if (fp != NULL) {
        /* Go to the end of the file. */
        if (fseek(fp, 0L, SEEK_END) == 0) {
            /* Get the size of the file. */
            long bufsize = ftell(fp);
            if (bufsize > 0) {
                /* Allocate our buffer to that size. */
# if USE_MMAPPED
                char *tptr = (char *)mremap(response.memory, response.allocsize, sizeof(char) * (bufsize + 2), MREMAP_MAYMOVE);
                if (tptr == MAP_FAILED || tptr == 0) {
                    /* out of memory! */
                    PRINT_ALLOC_ERROR(mremap);
                    *status = errno;                    // Return status
                    return response;
                }
# else
                char *tptr = (char *)realloc(response.memory, sizeof(char) * (bufsize + 2));
                if (tptr == NULL) {
                    /* out of memory! */
                    PRINT_ALLOC_ERROR(realloc);
                    *status = errno;                    // Return status
                    return response;
                }
# endif
# if DEBUG_MALLOC
                if (tptr!=response.memory) {
                    fprintf(stderr, "############# response.memory moved on step %d, d=%d\n", i, (long)(tptr-response.memory));
                }
# endif
                response.memory = tptr;
                /* Go back to the start of the file. */
                if (fseek(fp, 0L, SEEK_SET) != 0) { /* Error */ }

                /* Read the entire file into memory. */
                size_t newLen = fread(response.memory, sizeof(char), bufsize, fp);
                if (newLen == bufsize) {
                    response.memory[newLen+1] = '\0';   // Just to be safe
                    response.size = newLen;
                    response.http_code = 200;
                    *status = 0;                        // Return status
                } else { /* Error */ }
            }
        }
        if (ferror(fp)) {
            *status = errno;                            // Return status
            fprintf(stderr, "Error reading file '%s'\n", url);
        }
        fclose(fp);
    } else {
        fprintf(stderr, "Error opening file '%s'\n", url);
    }

    return response;                        // Return response structure
}



/*
 * Internal common function
 * Recognizes Frontier requirement
 */
static HttpResponse get_response(const char *url, const char *headers[], size_t nheaders, int timeout, int *status)
{
    const char *fp = "file://";
    char *frontierurl = "frontier://";
    if (strncmp(url,frontierurl,strlen(frontierurl))==0) {  //Check for Frontier URL
        return mget_frontier_response(url, headers, nheaders, timeout, status);
    }
    // const char *hp = "http://";

    // if (strncasecmp(url, fp, strlen(fp))==0) {

    //     return get_csv_file(url+strlen(fp), status);

    // } else
    {

        return mget_http_response(url, NULL, 0, headers, nheaders, timeout, status);

    }
}

//URL Parsing for Frontier
static void url_parser(const char *url, char *dburl, char *query)
{

    int slash_count = 0;                                    //Third slash separates URL from query
    int inside_parenthesis = 0;
    int char_count = 0;                                     //Character count
    fprintf(stdout,"URL is %s\n",url);

        for (int i = 0; url[i]!='\0'; i++) {                //Check entire URL
	    if (url[i] == '(') {
	        inside_parenthesis = 1;
			
	    } if (url[i] == ')') {
			inside_parenthesis = 0;
			
	    } if (inside_parenthesis == 0 && url[i] == '/') {
	        slash_count++;                              //Counts slashes outside parenthesis only
			
            } if (slash_count < 3) {
	        char_count++;                               //Counts characters up to the third slash
			
            } else {
	        break;
	    }
		    
	}

    strncpy(dburl,url,char_count);                          //Copies URL of database
    strcpy(query,(url+char_count+1));                       //Copies query
}

/*
 * Frontier response function
 */
static HttpResponse mget_frontier_response(const char *url, const char *headers[], size_t nheaders, int timeout, int *status)
{ 
    HttpResponse response;
    memset(&response,0,sizeof(response));
    int urllen = strlen(url);
    char *dburl = malloc(urllen);
    char *query = malloc(urllen);
    url_parser(url,dburl,query);

    /*Use frontier protocol */
    response.size=frontierretrieve(&response.state,&response.statelong,dburl,query,&response.memory);    
    response.http_code=200;
    free(dburl);
    free(query);
    return response;
}
/*
 * Internal common function
 */
static inline HttpResponse mget_response(const char *url, const char *urls[], size_t nurls, const char *headers[], size_t nheaders, int timeout, int *status)
{
    return mget_http_response(url, urls, nurls, headers, nheaders, timeout, status);
}


/*
 *
 */
void postHTTPsigned_retry(const char *url, const char* password, const char *headers[], size_t nheaders, const char *data, size_t length, int timeout, int *status)
{
    char salt[102];
    const char **hdrs = NULL;
    char *signature;
    char *args;
    char *mptr;
    int i;
    int ret;

    args = strchr(url, '?');                                        // Get the pointer to optional arguments
    if (args) args++;                                               // If get the arguments skip '?' character

    randStr(salt, sizeof (salt) - 2);                               // Generate salt
    signature = MD5Signature(password, salt, args, data, length);   // Generate MD5 signature

    hdrs = malloc(nheaders + 2);
    for (i = 0; i < nheaders; i++) {                                // Copy additional headers if provided
        hdrs[i] = headers[i];
    }

    mptr = malloc(128);                                             // Prepare X-Salt header
    ret = snprintf(mptr, 128, "X-Salt: %s", salt);
    if (ret >= 128) {                                               // Memory error
        fprintf(stderr, "Not enough space for the header\n");
    }
    hdrs[i++] = mptr;                                               // Add to headers list

    mptr = malloc(128);
    ret = snprintf(mptr, 128, "X-Signature: %s", signature);        // Prepare X-Signature header
    if (ret >= 128) {                                               // Memory error
        fprintf(stderr, "Not enough space for the header\n");
    }
    hdrs[i++] = mptr;                                               // Add to headers list

    postHTTP_retry(url, hdrs, nheaders+2, data, length, timeout, status);  // Post the data with additional headers

    free((void *)(hdrs[--i]));                                      // Free allocated memory
    free((void *)(hdrs[--i]));                                      // Free allocated memory
    free(hdrs);                                                     // Free allocated memory
}


void postHTTPsigned(const char *url, const char* password, const char *headers[], size_t nheaders, const char *data, size_t length, int *status)
{
    postHTTPsigned_retry(url, password, headers, nheaders, data, length, 0, status);
}


/*
 * The function communicates with the server using CURL library
 * It posts the databuffer of given size.
 *
 */
//  struct curl_slist *headerlist = NULL;
//
//  headerlist = curl_slist_append(headerlist, "X-Salt: .....");
//  headerlist = curl_slist_append(headerlist, "X-Signature: .....");
//
//  res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
//  ......
//  res = curl_easy_perform(curl);
//  ......
//  curl_easy_cleanup(curl);
//  ......
//  curl_slist_free_all(headerlist);
//
static void postHTTP_retry(const char *url, const char *headers[], size_t nheaders, const char *data, size_t length, int timeout, int *status)
{
    CURL *curl;
    CURLcode ret;
    int i;

    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);                       /* Pass the pointer to the data */
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)length);            /* Pass the data length         */
//      ret = curl_easy_perform(curl);                                          /* Do actual POST               */
        ret = perform_with_timeout(curl, NULL, url, NULL, 0, headers, nheaders, timeout, status);

        if (ret != CURLE_OK) {                                                  /* Check for errors             */
            fprintf(stderr, "%s: curl_easy_perform() failed: %s\n", __func__, curl_easy_strerror(ret));
        }
        curl_easy_cleanup(curl);                                                /* Cleanup                      */
    }
    *status = ret;
}


void postHTTP(const char *url, const char *headers[], size_t nheaders, const char *data, size_t length, int *status)
{
    postHTTP_retry(url, headers, nheaders, data, length, 0, status);
}


/*
 * The function communicates with the server using CURL library
 * It returns the structure which contains the array of rows as strings
 * along with its size.
 */
static HttpResponse get_data_rows(const char *url, const char *headers[], size_t nheaders, int timeout, int *status)
{
    int i, k;
    char *row;
    char *running;

    HttpResponse response = get_response(url, headers, nheaders, timeout, status);

# if DEBUG
    fprintf(stderr, "get_data_rows: %lu bytes retrieved\n", (long)response.size);
# endif
    if (response.http_code != 200) {
        return response;
    }
    /* Calculate the number of rows */
    for (i = 0, k = 0; i < response.size; i++) {
        if (response.memory[i]=='\n')
            k++;
    }
# if DEBUG
    fprintf(stderr, "get_data_rows: %d lines retrieved\n", k);
# endif
    /* Allocate memory for array of rows */
//  response.rows = (char **)malloc(sizeof(char *) * k + 8);
    response.rows = (char **)calloc(k+2, sizeof(char *));
    if (response.rows == NULL) {
        /* out of memory! */
        PRINT_ALLOC_ERROR(calloc);
        response.size = 0;
        return response;
    }
    response.nrows = k;

    /* Now break response to the rows */
    running = response.memory;                                  // Start from the beginning of the response buffer
    for (k = 0; (row = strsep(&running, "\n")); k++) {          // Walk through, find all newlines, replace them with '\0'
        //fprintf(stderr, "t = '%s'\n", row);
        //fprintf(stderr, "running = '%lx'\n", running);
        response.rows[k] = row;                                 // Store pointer to the line
    }

    return response;
}



/*
 * The function communicates with the server using CURL library
 * It returns the structure which contains the array of rows as strings
 * along with its size.
 */
static HttpResponse mget_data_rows(const char *url, const char *urls[], size_t nurls, const char *headers[], size_t nheaders, int timeout, int *status)
{
    int i, k;
    char *row;
    char *running;

    HttpResponse response = mget_response(url, urls, nurls, headers, nheaders, timeout, status);

# if DEBUG
    fprintf(stderr, "mget_data_rows: %lu bytes retrieved\n", (long)response.size);
# endif
    if (response.http_code != 200) {
        return response;
    }
    /* Calculate the number of rows */
    for (i = 0, k = 0; i < response.size; i++) {
      if (response.memory[i]=='\n')
          k++;
    }
# if DEBUG
    fprintf(stderr, "%s: %d lines retrieved\n", __func__, k);
# endif
    /* Allocate memory for array of rows */
//  response.rows = (char **)malloc(sizeof(char *) * k + 8);
    response.rows = (char **)calloc(k+2, sizeof(char *));
    if (response.rows == NULL) {
        /* out of memory! */
        PRINT_ALLOC_ERROR(calloc);
        response.size = 0;
        return response;
    }
    response.nrows = k;

    /* Now break response to the rows */
    running = response.memory;                                  // Start from the beginning of the response buffer
    for (k = 0; (row = strsep(&running, "\n")); k++) {          // Walk through, find all newlines, replace them with '\0'
        //fprintf(stderr, "t = '%s'\n", row);
        //fprintf(stderr, "running = '%lx'\n", running);
        response.rows[k] = row;                                 // Store pointer to the line
    }

    return response;
}



/*
 * The function deallocates used memory buffers.
 */
static int destroyHttpResponse(HttpResponse *response)
{
# if DEBUG_MALLOC
    statm_t stat;
    fprintf(stderr, "destroyHttpResponse: entered\n");
    read_off_memory_status(&stat);
# endif
    if (response!=NULL) {
        if (response->rows!=NULL) {
            free(response->rows);
            response->rows = NULL;
# if DEBUG_MALLOC
            fprintf(stderr, "destroyHttpResponse: response->rows destroyed\n");
            read_off_memory_status(&stat);
# endif
        }
	if (response->state!=NULL) {
		frontier_close(response->state, response->statelong);
	}
	else if (response->memory!=NULL) {
# if USE_MMAPPED
            munmap(response->memory, response->allocsize);
# else
            free(response->memory);
# endif
            response->memory = NULL;
# if DEBUG_MALLOC
            fprintf(stderr, "destroyHttpResponse: response->memory destroyed\n");
            read_off_memory_status(&stat);
# endif
        }
    }
    return 0;
}



/*
 * The function initializes response structure.
 */
static int initHttpResponse(HttpResponse *response)
{
    const size_t MIN_SIZE = 1024*1024;
# if USE_MMAPPED
    response->memory = (char *)mmap(NULL, MIN_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (response->memory == MAP_FAILED) {
        PRINT_ALLOC_ERROR(mmap);
        response->memory = NULL;
        return -1;
    }
    response->allocsize = MIN_SIZE;
# else
    response->memory = (char *)malloc(MIN_SIZE);    /* will be grown as needed by realloc   */
    if (response->memory == NULL) {
        PRINT_ALLOC_ERROR(malloc);
        response->memory = NULL;
        return -1;
    }
    response->allocsize = MIN_SIZE;
    response->memory[0] = '\0';             /* Zero byte                                    */
# endif
    response->rows = NULL;                  /* no data at this point                        */
    response->nrows = response->size = 0;   /* no data at this point                        */
    response->http_code = 0;
    response->state = 0;
    return 0;
}



/*
 * The function deallocates used memory buffers.
 */
static int destroyDataRec(DataRec *dataRec)
{
    if (dataRec!=NULL) {
        if (dataRec->columns!=NULL) {
            if (dataRec->columns[0]!=NULL) {
                free(dataRec->columns[0]);
            }
            free(dataRec->columns);
            dataRec->columns = NULL;
        }
        free(dataRec);
    }
    return 0;
}

/*
 * Function to parse one row in CSV format.
 */
static DataRec *parse_csv_row(const char *s)
{
    char *cp;
    char *sp;
    char *qp;
    char *tp;
    int len;
    int i, j, ncol, inquotes;
    register char *ss;

    ss = strdup(s);
    if (ss == NULL) {
        /* out of memory! */
        PRINT_ALLOC_ERROR(strdup);
        return NULL;
    }

    DataRec *dataRec = (DataRec *)malloc(sizeof (DataRec));
    dataRec = (DataRec *)memset(dataRec, 0, sizeof (DataRec));

    {
        //
        // Find the number of columns
        //
# if 0
        for (sp = ss, ncol = 0, inquotes = 0; *sp; sp++) {
            if (*sp=='"') inquotes = !inquotes;
            if (inquotes) continue;
            if (*sp==',') ncol++;
        }
# else
        int fidx;
        for (sp = ss, ncol = 0, inquotes = 0, fidx = 0; *sp; sp++, fidx++) {
            if (fidx == 0 && *sp == '"') {
                inquotes = !inquotes;
                continue;
            }
            if (inquotes) {
                if (*sp == '"' && *(sp+1) == '"') {
                    sp++;                       // If in quotes and see double-quote pair skip them
                } else if (*sp == '"') {
                    inquotes = !inquotes;
                    continue;                   // Go to the next symbol
                }
            } else {
                if (*sp == ',') {               // Count commas if not in quotes
                    ncol++;
                    fidx = -1;
                }
            }
        }
# endif
# if DEBUG
        fprintf(stderr, "%s: ncol=%d\n", __func__, ncol);
#endif
        dataRec->ncolumns = ++ncol;                                 // Store the number of columns

//      size_t csize = sizeof(char *) * dataRec->ncolumns;          // Allocated memory size
//      dataRec->columns = (char **)malloc(csize);                  // Allocate pointers to column data
        dataRec->columns = (char **)calloc(dataRec->ncolumns, sizeof(char *));  // Allocate pointers to column data
        if (dataRec->columns == NULL) {
            /* out of memory! */
            PRINT_ALLOC_ERROR(calloc);
            return NULL;
        }
//      memset(dataRec->columns, 0, csize);                         // Clear the column pointers

        sp = ss;                                                    // Start from the begining of the line
        //fprintf(stderr, "parse_csv: s='%s'\n", ss);
# if 0
        for (cp = sp = ss, ncol = 0, inquotes = 0; ncol < dataRec->ncolumns; sp++) {
            if (*sp=='"') inquotes = !inquotes;
            if (inquotes) continue;
            if (*sp==',' || *sp=='\0') {
                dataRec->columns[ncol++] = cp;                      // Store the pointer to the name
                *sp = '\0';
# if DEBUG
                fprintf(stderr, "%s: col='%s'\n", __func__, cp);
#endif
                cp = sp + 1;
            }
        }
# else
        // for (cp = sp = tp = ss, ncol = inquotes = fidx = 0; ncol < dataRec->ncolumns, *sp; sp++, tp++, fidx++) {
        for (cp = sp = tp = ss, ncol = inquotes = fidx = 0; ncol < dataRec->ncolumns; sp++, tp++, fidx++) {
            if (fidx == 0 && *sp == '"') {          // Quoted string can start only right after the delimiter
                inquotes = !inquotes;               // We are in quoted string, set the flag
                tp--;                               // Adjust target pointer to overwrite opening double-quote
                continue;                           // Go to the next symbol
            }
            if (inquotes) {
                if (*sp == '"' && *(sp+1) == '"') { // Found a double-quote pair
                    sp++;                           // If in quotes and see double-quote pair skip one
                } else if (*sp == '"') {            // Found а solitary double-quote symbol closing a string
                    inquotes = !inquotes;           // We are leaving quoted string, reset the flag
                    tp--;                           // Adjust target pointer to skip closing double-quote symbol
                    continue;                       // Go to the next symbol
                }
                *tp = *sp;                          // Copy source string character to target position
            } else {                                // We are not in quoted string
                if (*sp==',' || *sp=='\0') {        // Found the delimiter
                    dataRec->columns[ncol++] = cp;  // Store the pointer to the beginning of the field
                    fidx = -1;                      // Reset index inside field
                    *sp = '\0';                     // Replace ',' with zero byte to terminate the field
                    *tp = '\0';                     // If it was quoted string terminate processed string
                    tp = sp;                        // Field ended, reset target pointer to current source pointer
                    cp = sp + 1;                    // Set column pointer to the beginning of the next column
                    // *tp = '\xa4';                   // Debug
                    // *sp = ';';                      // Debug
                }
            }
        }
#endif
    }
//    fprintf(stderr, "parse_csv: allocated=%d(hdr)+%d(arr)+%d(str)\n", sizeof(DataRec), csize, strlen(s));
    return dataRec;
}


/*
 * Low level generic function which returns the whole dataset
 */
Dataset getDataWithTimeout(const char *url, const char *uagent, int timeout, int *error)
{
    int err;
    HttpResponse *response;
    char user_agent[256];
# if 0
    statm_t stat;
# endif

    snprintf(user_agent, 256, "User-Agent: %s", uagent);
    const char *headers[] = {user_agent, NULL};
# if DEBUG
    fprintf(stderr, "getDataWithTimeout: url='%s'\n", url);
# endif
    *error = errno = 0;
    response = (HttpResponse *)malloc(sizeof (HttpResponse));
    if (response == NULL) {
        /* out of memory! */
        PRINT_ALLOC_ERROR(malloc);
        *error = errno;
        return NULL;
    }
    *response = get_data_rows(url, headers, 1, timeout, &err);
# if 0
    fprintf(stderr, "getDataWithTimeout: after get_data_rows call\n");
    read_off_memory_status(&stat);
# endif
    if (err) {
        *error = errno = ENODATA;
    }
    /* Now grow the response structure to allocate space for dataRecs array */
    response = (HttpResponse *)realloc(response, sizeof (HttpResponse) + response->nrows*sizeof(DataRec *));
    if (response == NULL) {
        /* out of memory! */
        PRINT_ALLOC_ERROR(realloc);
        *error = errno;
        return NULL;
    }
    /* Important! Must be zeroed - code relies on it */
    memset(response->dataRecs, 0, response->nrows*sizeof(DataRec *));
# if 0
    fprintf(stderr, "getDataWithTimeout: after allocating space for dataRecs array (%d * %d)\n", response->nrows, sizeof(DataRec *));
    read_off_memory_status(&stat);
# endif

    return (Dataset)response;
}


/*
 * Low level generic function which returns the whole dataset.
 * Retries the request while total time is less than specified timeout.
 */
Dataset muxGetDataWithTimeout(const char *url, const char *urls[], size_t nurls, const char *uagent, int timeout, int *error)
{
    int err;
    HttpResponse *response;
    char user_agent[256];
# if 0
    statm_t stat;
# endif

    snprintf(user_agent, sizeof (user_agent), "User-Agent: %s", uagent);
    const char *headers[] = {user_agent, NULL};
# if DEBUG
    fprintf(stderr, "muxGetDataWithTimeout: url='%s'\n", url);
# endif
    *error = errno = 0;
    response = (HttpResponse *)malloc(sizeof (HttpResponse));
    if (response == NULL) {
        /* out of memory! */
        PRINT_ALLOC_ERROR(malloc);
        *error = errno;
        return NULL;
    }
    *response = mget_data_rows(url, urls, nurls, headers, 1, timeout, &err);
# if 0
    fprintf(stderr, "muxgetDataWithTimeout: after get_data_rows call\n");
    read_off_memory_status(&stat);
# endif
    if (err) {
        *error = errno = ENODATA;
    }
    /* Now grow the response structure to allocate space for dataRecs array */
    response = (HttpResponse *)realloc(response, sizeof (HttpResponse) + response->nrows*sizeof(DataRec *));
    if (response == NULL) {
        /* out of memory! */
        PRINT_ALLOC_ERROR(realloc);
        *error = errno;
        return NULL;
    }
    /* Important! Must be zeroed - code relies on it */
    memset(response->dataRecs, 0, response->nrows*sizeof(DataRec *));
# if 0
    fprintf(stderr, "muxgetDataWithTimeout: after allocating space for dataRecs array (%d * %d)\n", response->nrows, sizeof(DataRec *));
    read_off_memory_status(&stat);
# endif

    return (Dataset)response;
}


/*
 * Low level generic function which returns the whole dataset.
 */
Dataset getData(const char *url, const char *uagent, int *error)
{
    return getDataWithTimeout(url, uagent, 0, error);
}


int getNtuples(Dataset dataset)
{
    HttpResponse *response;

    response = (HttpResponse *)dataset;
    return response->nrows;
}


int getIndex(Dataset dataset)
{
    HttpResponse *response;

    response = (HttpResponse *)dataset;
    return response->idx;
}


Tuple getTuple(Dataset dataset, int idx)
{
    HttpResponse *response;
    DataRec *dataRec;

    response = (HttpResponse *)dataset;
    if (idx < 0 || idx >= response->nrows) {
        errno = ENODATA;
        return NULL;
    }
    if (response->dataRecs[idx]) {
//    fprintf(stderr, "Get from cache\n");
        dataRec = response->dataRecs[idx];
    } else {
//    fprintf(stderr, "Store in cache\n");
        dataRec = parse_csv_row(response->rows[idx]);       // parse the line
        response->dataRecs[idx] = dataRec;
    }
    (response->idx) = idx + 1;
    return (Tuple)(dataRec);
}


int getNfields(Tuple tuple)
{
    DataRec *dataRec = (DataRec *)tuple;
    return dataRec->ncolumns;
}


Tuple getFirstTuple(Dataset dataset)
{
    return getTuple(dataset, 0);
}


Tuple getNextTuple(Dataset dataset)
{
    HttpResponse *response;

    response = (HttpResponse *)dataset;

    return getTuple(dataset, response->idx);
}


long getLongValue(Tuple tuple, int position, int *error)
{
    DataRec *dataRec = (DataRec *)tuple;
    if (position < 0 || position >= dataRec->ncolumns) {
        *error = EINVAL;
        return LONG_MIN;
    }
    errno = 0;
    long val = strtol(dataRec->columns[position], NULL, 10);
//    fprintf(stderr,"getIntValue: converting '%s'\n", dataRec->columns[position]);
//    fprintf(stderr,"getIntValue: returning %ld, errno=%d\n", val, errno);
    *error = errno;
    return val;
}

double getDoubleValue(Tuple tuple, int position, int *error)
{
    DataRec *dataRec = (DataRec *)tuple;
    if (position < 0 || position >= dataRec->ncolumns) {
        *error = EINVAL;
        return LONG_MIN;
    }
    errno = 0;
    double val = strtod(dataRec->columns[position], NULL);
    *error = errno;
    return val;
}


int getStringValue(Tuple tuple, int position, char *buffer, int buffer_size, int *error)
{
    char *cp;
    DataRec *dataRec = (DataRec *)tuple;
    if (position < 0 || position >= dataRec->ncolumns) {
        *error = EINVAL;
        return -1;
    }
////strncpy(buffer, dataRec->columns[position], buffer_size);
    *error = 0;
    if (dataRec->columns[position] > 0) {
        cp = memccpy(buffer, dataRec->columns[position], 0, buffer_size-1);
        if (cp==NULL) {                         // There was no enough space in the destination buffer
            buffer[buffer_size-1] = '\0';       // Terminate the string
            *error = EINVAL;
        }
        return strlen(buffer);
    }
    *error = EINVAL;
    return -1;
}

int getDoubleArray(Tuple tuple, int position, double *buffer, int buffer_size, int *error)
{
    DataRec *dataRec = (DataRec *)tuple;
    if (position < 0 || position >= dataRec->ncolumns) {
        *error = EINVAL;
        return 0;
    }
    int i, len;
    double val;
    char *sptr;
    char *eptr;

    errno = 0;
    sptr = dataRec->columns[position];              // Start from the beginning of array
    if (strncmp(sptr, "\"[", 2)==0)
        sptr += 2;                                  // Skip double quote and square bracket
    else if (*sptr == '[')
        sptr += 1;                                  // Skip square bracket
    for (len = i = 0; i < dataRec->ncolumns-position; i++) {
        val = strtod(sptr, &eptr);                  // Try to convert
        if (sptr==eptr) break;                      // End the loop if no coversion was performed
        if (*sptr=='\0') break;                     // End the loop if buffer ends
        if (errno) break;                           // Error in decoding
# if DEBUG
        fprintf(stderr, "%s: decoded '%s' ", __func__, sptr);
        fprintf(stderr, "[%d]<-%f\n", i, val);
# endif
        if (len < buffer_size)
            buffer[len] = val;                      // Store converted value, increase the length
        len++;
        sptr = eptr + 1;                            // Shift the pointer to the next number
    }
    if (i > buffer_size && errno == 0)
        *error = ENOBUFS;
    else
        *error = errno;
    return len;
}

int getLongArray(Tuple tuple, int position, long *buffer, int buffer_size, int *error)
{
    DataRec *dataRec = (DataRec *)tuple;
    if (position < 0 || position >= dataRec->ncolumns) {
        *error = EINVAL;
        return 0;
    }
    int i, len;
    long val;
    char *sptr;
    char *eptr;

    errno = 0;
    sptr = dataRec->columns[position];              // Start from the beginning of array
    if (strncmp(sptr, "\"[", 2)==0)
        sptr += 2;                                  // Skip double quote and square bracket
    else if (*sptr == '[')
        sptr += 1;                                  // Skip square bracket
    for (len = i = 0; i < dataRec->ncolumns-position; i++) {
        val = strtol(sptr, &eptr, 10);              // Try to convert
        if (sptr==eptr) break;                      // End the loop if no coversion was performed
        if (*sptr=='\0') break;                     // End the loop if buffer ends
        if (len < buffer_size)
            buffer[len] = val;                      // Store converted value, increase the length
        len++;
        sptr = eptr + 1;                            // Shift the pointer to the next number
    }
    if (i > buffer_size && errno == 0)
        *error = ENOBUFS;
    else
        *error = errno;
    return len;
}


int releaseDataset(Dataset dataset)
{
    int i;
    HttpResponse *response = (HttpResponse *)dataset;
    if (response == NULL)
        return 0;
    /* First, release all stored dataRecs   */
# if DEBUG_MALLOC
    statm_t stat;
    fprintf(stderr, "releaseDataset: entered\n");
    read_off_memory_status(&stat);
# endif
    for (i = 0; i < response->nrows; i++) {
        if (response->dataRecs[i] > 0) {
# if DEBUG
            fprintf(stderr, "releaseDataset: destroyDataRec %d\n", i);
# endif
            destroyDataRec(response->dataRecs[i]);
            response->dataRecs[i] = NULL;
        }
    }
# if DEBUG_MALLOC
    fprintf(stderr, "releaseDataset: response->dataRecs[0:%d] destroyed\n", response->nrows);
    read_off_memory_status(&stat);
# endif
    /* Second, release dataset itself       */
# if DEBUG
    fprintf(stderr, "releaseDataset: about to free %p\n", dataset);
# endif
    destroyHttpResponse((HttpResponse *)dataset);
    free(dataset);
# if DEBUG_MALLOC
    fprintf(stderr, "releaseDataset: response data destroyed\n");
    read_off_memory_status(&stat);
# endif
    return 0;
}


int releaseTuple(Tuple tuple)
{
# if 0
    return destroyDataRec((DataRec *)tuple);
# else
    return 0;
# endif
}

long getHTTPstatus(Dataset dataset)
{
    return ((HttpResponse *)dataset)->http_code;
}

char *getHTTPmessage(Dataset dataset)
{
    return ((HttpResponse *)dataset)->memory;
}
