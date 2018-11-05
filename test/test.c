

#include "../c/httpc.c"
#include "../c/membuf.c"



char* request_get(char* head, char * path, char* query)
{
    char* context = "text/html";
    char* cookie = "";

    return igr_response(200, context, cookie, query);
}

char* request_post(char* head, char * path, char* payload)
{
    char* context = "text/html";
    char* cookie = "";

    return igr_response(200, context, cookie, payload);
}

igr_res _request_get = &request_get;
igr_res _request_post = &request_post;

int main(void)
{
    char* static_path = "/static/path/";
    char* ip = "0.0.0.0";
    
    igr_handle_request( _request_get, _request_post);
    igr_init ( static_path, ip, 8080 );
}


