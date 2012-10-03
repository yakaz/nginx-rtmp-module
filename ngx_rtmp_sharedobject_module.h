
#ifndef _NGX_RTMP_SHAREDOBJECT_H_INCLUDED_
#define _NGX_RTMP_SHAREDOBJECT_H_INCLUDED_

#include <ngx_core.h>

#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"


typedef struct ngx_rtmp_sharedobject_s ngx_rtmp_sharedobject_t;
typedef struct ngx_rtmp_sharedobject_ctx_s ngx_rtmp_sharedobject_ctx_t;
typedef struct ngx_rtmp_sharedobject_list_s ngx_rtmp_sharedobject_list_t;
typedef struct ngx_rtmp_sharedobject_prop_s ngx_rtmp_sharedobject_prop_t;

struct ngx_rtmp_sharedobject_prop_s {
  ngx_rtmp_sharedobject_prop_t  *next;
  u_char                        *name;
  u_char                        *value;
  uint16_t                       name_len;
  uint32_t                       value_len;
};

struct ngx_rtmp_sharedobject_ctx_s {
  ngx_rtmp_session_t            *session;
  ngx_rtmp_sharedobject_list_t  *shared_objects;
  ngx_rtmp_sharedobject_ctx_t   *next;
};


struct ngx_rtmp_sharedobject_s {
  u_char                         name[NGX_RTMP_MAX_NAME];
  ngx_rtmp_sharedobject_t       *next;
  ngx_rtmp_sharedobject_ctx_t   *ctx;
  ngx_rtmp_sharedobject_prop_t  *prop;
  uint32_t                       version;
  int                            persistent;
  /* TODO */
};


struct ngx_rtmp_sharedobject_list_s {
  ngx_rtmp_sharedobject_t       *shared_object;
  ngx_rtmp_sharedobject_list_t  *next;
};


typedef struct {
  ngx_int_t                      nbuckets;
  ngx_rtmp_sharedobject_t      **shared_objects;
  ngx_pool_t                    *pool;
  ngx_rtmp_sharedobject_t       *free_shared_objects;
} ngx_rtmp_sharedobject_app_conf_t;


extern ngx_module_t  ngx_rtmp_sharedobject_module;



#endif /* _NGX_RTMP_SHAREDOBJECT_H_INCLUDED_ */
