

#include "../c/httpc.c"
#include "../c/membuf.c"



char* request_get(const char* head, const char * path, const char* query)
{
    char* context = "text/html";
    char* cookie = "";

    return igr_response(200, context, cookie, query);
}

char* request_post(const char* head, const char * path, const char* payload)
{
    char* context = "text/html";
    char* cookie = "";

    return igr_response(200, context, cookie, payload);
}

int main(void)
{
    char* static_path = "/static/path/";
    char* ip = "0.0.0.0";
    
    igr_handle_request( request_get, request_post);
    igr_init ( static_path, ip, 8080 );
}


