#include "ngx_rtmp_sharedobject_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_streams.h"

static ngx_int_t ngx_rtmp_sharedobject_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_sharedobject_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_sharedobject_merge_app_conf(ngx_conf_t *cf,
                                                   void *parent, void *child);


static ngx_rtmp_module_t  ngx_rtmp_sharedobject_module_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_rtmp_sharedobject_postconfiguration, /* postconfiguration */
    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */
    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */
    ngx_rtmp_sharedobject_create_app_conf,   /* create app configuration */
    ngx_rtmp_sharedobject_merge_app_conf     /* merge app configuration */
};


ngx_module_t  ngx_rtmp_sharedobject_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_sharedobject_module_ctx,       /* module context */
    NULL,                                    /* module directives */
    NGX_RTMP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};

// FIXME: use free_sharedobject like free_streams in live_module

static void *
ngx_rtmp_sharedobject_create_app_conf(ngx_conf_t *cf)
{
  ngx_rtmp_sharedobject_app_conf_t      *soacf;

  soacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_sharedobject_app_conf_t));

  if (soacf == NULL) {
    return NULL;
  }

  soacf->nbuckets = NGX_CONF_UNSET;

  return soacf;
}


static char *
ngx_rtmp_sharedobject_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_rtmp_sharedobject_app_conf_t *prev = parent;
  ngx_rtmp_sharedobject_app_conf_t *conf = child;

  ngx_conf_merge_value(conf->nbuckets, prev->nbuckets, 1024);

  conf->pool = ngx_create_pool(4096, &cf->cycle->new_log);
  if (conf->pool == NULL) {
    return NGX_CONF_ERROR;
  }

  conf->shared_objects =
    ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_sharedobject_t *) * conf->nbuckets);

  return NGX_CONF_OK;
}


/*************************************************************************/
static ngx_rtmp_sharedobject_t **
ngx_rtmp_sharedobject_search(ngx_rtmp_session_t *s, u_char *name,
                             uint32_t flags, int create)
{
  ngx_rtmp_sharedobject_app_conf_t    *soacf;
  ngx_rtmp_sharedobject_t            **so;
  size_t                               len;

  soacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_sharedobject_module);
  if (soacf == NULL) {
    return NULL;
  }

  len = ngx_strlen(name);
  so  = &(soacf->shared_objects[ngx_hash_key(name, len) % soacf->nbuckets]);

  for (; *so; so = &(*so)->next) {
    if (ngx_strcmp(name, (*so)->name) == 0) {
      return so;
    }
  }

  if (!create) {
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "shared-object: '%s' not found", name);
    return NULL;
  }

  ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                 "shared-object: create '%s'", name);

  if (soacf->free_shared_objects) {
    *so = soacf->free_shared_objects;
    soacf->free_shared_objects = soacf->free_shared_objects->next;
  }
  else {
    *so = ngx_palloc(soacf->pool, sizeof(ngx_rtmp_sharedobject_t));
  }
  ngx_memzero(*so, sizeof(ngx_rtmp_sharedobject_t));
  ngx_memcpy((*so)->name, name, ngx_min(sizeof((*so)->name) - 1, len));
  (*so)->version = 0;
  (*so)->persistent = (flags != 0);

  return so;
}


static ngx_rtmp_sharedobject_t **
ngx_rtmp_sharedobject_get(ngx_rtmp_session_t *s, u_char *name)
{
  ngx_rtmp_sharedobject_ctx_t         *ctx;
  ngx_rtmp_sharedobject_list_t        *solist;
  ngx_rtmp_sharedobject_t            **so;

  ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_sharedobject_module);
  if (ctx == NULL) {
    return NULL;
  }

  for (solist = ctx->shared_objects; solist; solist = solist->next) {
    so = &(solist->shared_object);
    if (ngx_strcmp(name, (*so)->name) == 0) {
      return so;
    }
  }

  return NULL;
}


static ngx_rtmp_sharedobject_t **
ngx_rtmp_sharedobject_use(ngx_rtmp_session_t *s, u_char *name,
                          uint32_t flags)
{
  ngx_rtmp_sharedobject_ctx_t         *ctx;
  ngx_rtmp_sharedobject_list_t        *solist;
  ngx_rtmp_sharedobject_t            **so;


  ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_sharedobject_module);
  if (ctx == NULL) {
    ctx = ngx_pcalloc(s->connection->pool,
                      sizeof(ngx_rtmp_sharedobject_ctx_t));
    ctx->session = s;
    ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_sharedobject_module);
  }

  so = ngx_rtmp_sharedobject_get(s, name);
  if (so != NULL) {
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "shared-object: '%s' already in use", name);
    return so;
  }

  so = ngx_rtmp_sharedobject_search(s, name, flags, 1);
  if (so == NULL) {
    return NULL;
  }

  ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                 "shared-object: use '%s'", name);

  ctx->next = (*so)->ctx;
  (*so)->ctx = ctx;

  solist = ngx_pcalloc(s->connection->pool,
                       sizeof(ngx_rtmp_sharedobject_list_t));
  solist->shared_object = *so;
  solist->next = ctx->shared_objects;
  ctx->shared_objects = solist;

  return so;
}


static ngx_int_t
ngx_rtmp_sharedobject_use_success(ngx_rtmp_session_t *s,
                                  ngx_rtmp_sharedobject_t *so)
{
  ngx_rtmp_sharedobject_prop_t *prop;
  ngx_rtmp_header_t             h;

  static uint32_t               zero    = 0;
  static uint32_t               success = NGX_RTMP_SHARED_USE_SUCCESS;
  static ngx_rtmp_amf_elt_t     out_elts[] = {
    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &zero, 0 },

    { NGX_RTMP_AMF_INT8 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &success, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &zero, 0 },
  };

  out_elts[0].data = so->name;
  out_elts[1].data = &(so->version);
  out_elts[2].data = (uint32_t[]){(so->persistent) ? 34 : 0};

  ngx_memzero(&h, sizeof(h));
  h.type = NGX_RTMP_MSG_AMF_SHARED;
  h.csid = NGX_RTMP_CSID_SHARED;
  h.msid = 0;

  return (ngx_rtmp_send_amf(s, &h, out_elts,
                            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    ? NGX_ERROR
    : NGX_OK;
}


/*************************************************************************/
static ngx_int_t
ngx_rtmp_sharedobject_release(ngx_rtmp_session_t *s,
                              ngx_rtmp_sharedobject_t *so)
{
  ngx_rtmp_sharedobject_ctx_t         *ctx, **cctx;
  ngx_rtmp_sharedobject_app_conf_t    *soacf;
  ngx_rtmp_sharedobject_list_t        *solist, *prev;
  ngx_rtmp_sharedobject_prop_t        *prop;
  ngx_rtmp_sharedobject_t            **freeso;


  soacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_sharedobject_module);
  if (soacf == NULL) {
    return NGX_ERROR;
  }

  ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_sharedobject_module);
  if (ctx == NULL) {
    return NGX_ERROR;
  }

  for (prev=NULL, solist = ctx->shared_objects;
       solist;
       prev = solist, solist = solist->next) {
    if (so == solist->shared_object) {
      ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                     "shared-object: release '%s'", so->name);

      if (prev == NULL) {
        ctx->shared_objects = solist->next;
      }
      else {
        prev->next = solist->next;
      }
      ngx_pfree(s->connection->pool, solist);

      for (cctx = &(so->ctx); *cctx; cctx = &((*cctx)->next)) {
        if (*cctx == ctx) {
          *cctx = ctx->next;
          break;
        }
      }

      if (so->ctx) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "shared-object: do not remove '%s' (still in use)",
                       so->name);
      }
      else if (so->persistent) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "shared-object: do not remove '%s' (persistent)",
                       so->name);
      }
      else {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "shared-object: remove '%s'", so->name);
        while (so->prop) {
          prop     = so->prop;
          so->prop = prop->next;


          ngx_pfree(soacf->pool, prop->name);
          ngx_pfree(soacf->pool, prop->value);
          ngx_pfree(soacf->pool, prop);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "shared-object: free '%s'", so->name);

        freeso = ngx_rtmp_sharedobject_search(s, so->name, 0, 0);
        if (freeso != NULL) {
          *freeso = (*freeso)->next;
        }

        so->next = soacf->free_shared_objects;
        soacf->free_shared_objects = so;
      }
      break;
    }
  }

  return NGX_OK;
}




/*************************************************************************/
static ngx_int_t
ngx_rtmp_sharedobject_sendmsg(ngx_rtmp_session_t *s,
                              ngx_rtmp_sharedobject_t *so,
                              u_char *data, uint32_t len)
{
  ngx_rtmp_sharedobject_ctx_t *ctx;
  ngx_rtmp_header_t            h;

  static uint32_t              zero = 0;
  static uint32_t              send = NGX_RTMP_SHARED_SEND_MESSAGE;
  static ngx_rtmp_amf_elt_t    out_elts[] = {
    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &zero, 0 },

    { NGX_RTMP_AMF_INT8 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &send, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0},

    { NGX_RTMP_AMF_RAWDATA | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0},
  };

  out_elts[0].data = so->name;
  out_elts[1].data = &(so->version);
  out_elts[2].data = (uint32_t[]){(so->persistent) ? 34 : 0};
  out_elts[5].data = &len;
  out_elts[6].data = data;
  out_elts[6].len  = len;

  ngx_memzero(&h, sizeof(h));
  h.type = NGX_RTMP_MSG_AMF_SHARED;
  h.csid = NGX_RTMP_CSID_SHARED;

  for (ctx = so->ctx; ctx; ctx = ctx->next) {
    if (ctx->session != s) {
      ngx_rtmp_send_amf(ctx->session, &h, out_elts,
                        sizeof(out_elts) / sizeof(out_elts[0]));
    }
  }

  return (ngx_rtmp_send_amf(s, &h, out_elts,
                            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    ? NGX_ERROR
    : NGX_OK;
}



static ngx_int_t
ngx_rtmp_sharedobject_status(ngx_rtmp_session_t *s,
                             ngx_rtmp_sharedobject_t *so,
                             u_char *code, u_char *level)
{
  ngx_rtmp_header_t             h;

  static uint32_t               zero   = 0;
  static uint32_t               status = NGX_RTMP_SHARED_STATUS;
  static ngx_rtmp_amf_elt_t     out_elts[] = {
    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &zero, 0 },

    { NGX_RTMP_AMF_INT8 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &status, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },
  };

  out_elts[0].data = so->name;
  out_elts[1].data = &(so->version);
  out_elts[2].data = (uint32_t[]){(so->persistent) ? 34 : 0};
  out_elts[5].data = (uint32_t[]){4 + ngx_strlen(code) + ngx_strlen(level)};
  out_elts[6].data = code;
  out_elts[7].data = level;

  ngx_memzero(&h, sizeof(h));
  h.type = NGX_RTMP_MSG_AMF_SHARED;
  h.csid = NGX_RTMP_CSID_SHARED;
  h.msid = 0;

  return (ngx_rtmp_send_amf(s, &h, out_elts,
                            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    ? NGX_ERROR
    : NGX_OK;
}


/*************************************************************************/
static ngx_rtmp_sharedobject_prop_t *
ngx_rtmp_sharedobject_search_prop(ngx_rtmp_session_t *s,
                                  ngx_rtmp_sharedobject_t *so,
                                  u_char *name)
{
  ngx_rtmp_sharedobject_prop_t *prop;

  for (prop = so->prop; prop; prop = prop->next) {
    if (ngx_strcmp(name, prop->name) == 0) {
      return prop;
    }
  }
  return NULL;
}

static ngx_rtmp_sharedobject_prop_t *
ngx_rtmp_sharedobject_request_change(ngx_rtmp_session_t *s,
                                     ngx_rtmp_sharedobject_t *so,
                                     u_char *data, uint32_t len)
{
  ngx_rtmp_sharedobject_app_conf_t    *soacf;
  ngx_rtmp_sharedobject_prop_t        *prop;
  u_char                              *name, *value, *p;
  uint16_t                             sz;

  soacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_sharedobject_module);
  if (soacf == NULL) {
    return NULL;
  }

  /* read property name */
  p = (u_char*)&sz;
  p[0] = data[1];
  p[1] = data[0];

  name = ngx_pcalloc(soacf->pool, sizeof(u_char) * sz);
  ngx_memcpy(name, data+2, sz);

  /* read property value */
  value = ngx_pcalloc(soacf->pool, sizeof(u_char) * (len-sz));
  ngx_memcpy(value, data+2+sz, (len-sz));

  /* Store the property */
  prop = ngx_rtmp_sharedobject_search_prop(s, so, name);
  if (prop == NULL) {
    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "shared-object: set property '%s' in '%s'",
                   name, so->name);
    prop = ngx_pcalloc(soacf->pool, sizeof(ngx_rtmp_sharedobject_prop_t));
    prop->name      = name;
    prop->name_len  = sz;
    prop->value     = value;
    prop->value_len = len-sz;
    prop->next      = so->prop;
    so->prop        = prop;
  }
  else {
    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "shared-object: update property '%s' in '%s'",
                   name, so->name);
    ngx_pfree(soacf->pool, name);
    ngx_pfree(soacf->pool, prop->value);
    prop->value = value;
    prop->value_len = len-sz;
  }

  return prop;
}


static ngx_int_t
ngx_rtmp_sharedobject_success(ngx_rtmp_session_t *s,
                              ngx_rtmp_sharedobject_t *so,
                              u_char *name, ngx_int_t len)
{
  ngx_rtmp_header_t            h;

  static uint32_t              zero    = 0;
  static uint32_t              success = NGX_RTMP_SHARED_SUCCESS;
  static ngx_rtmp_amf_elt_t    out_elts[] = {
    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &zero, 0 },

    { NGX_RTMP_AMF_INT8 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &success, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0},

    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0}
  };

  out_elts[0].data = so->name;
  out_elts[1].data = &(so->version);
  out_elts[2].data = (uint32_t[]){(so->persistent) ? 34 : 0};
  out_elts[5].data = (uint32_t[]){2+len};
  out_elts[6].data = name;

  ngx_memzero(&h, sizeof(h));
  h.type = NGX_RTMP_MSG_AMF_SHARED;
  h.csid = NGX_RTMP_CSID_SHARED;

  return (ngx_rtmp_send_amf(s, &h, out_elts,
                            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    ? NGX_ERROR
    : NGX_OK;
}


static ngx_int_t
ngx_rtmp_sharedobject_change(ngx_rtmp_session_t *s,
                             ngx_rtmp_sharedobject_t *so,
                             ngx_rtmp_sharedobject_prop_t *prop)
{
  ngx_rtmp_header_t            h;

  static uint32_t              zero   = 0;
  static uint32_t              change = NGX_RTMP_SHARED_CHANGE;
  static ngx_rtmp_amf_elt_t    out_elts[] = {
    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &zero, 0 },

    { NGX_RTMP_AMF_INT8 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &change, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0},

    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0},

    { NGX_RTMP_AMF_RAWDATA | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0},
  };

  out_elts[0].data = so->name;
  out_elts[1].data = &(so->version);
  out_elts[2].data = (uint32_t[]){(so->persistent) ? 34 : 0};
  out_elts[5].data = (uint32_t[]){2+prop->name_len+prop->value_len};
  out_elts[6].data = prop->name;
  out_elts[6].len  = prop->name_len;
  out_elts[7].data = prop->value;
  out_elts[7].len  = prop->value_len;

  ngx_memzero(&h, sizeof(h));
  h.type = NGX_RTMP_MSG_AMF_SHARED;
  h.csid = NGX_RTMP_CSID_SHARED;

  return (ngx_rtmp_send_amf(s, &h, out_elts,
                            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    ? NGX_ERROR
    : NGX_OK;
}


/*************************************************************************/
static ngx_int_t
ngx_rtmp_sharedobject_request_remove(ngx_rtmp_session_t *s,
                                     ngx_rtmp_sharedobject_t *so,
                                     u_char *name, uint32_t len)
{
  ngx_rtmp_sharedobject_app_conf_t    *soacf;
  ngx_rtmp_sharedobject_prop_t        *prop, *prev;
  u_char                              *p;

  soacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_sharedobject_module);
  if (soacf == NULL) {
    return NGX_ERROR;
  }

  for (prev = NULL, prop = so->prop;
       prop;
       prev = prop, prop = prop->next) {
    if (ngx_strncmp(prop->name, name, len) == 0)
      break;
  }

  if (prop != NULL) {
    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "shared-object: remove property '%s' in '%s'",
                   prop->name, so->name);
    if (prev == NULL) {
      so->prop = prop->next;
    }
    else {
      prev->next = prop->next;
    }
    ngx_pfree(soacf->pool, prop->name);
    ngx_pfree(soacf->pool, prop->value);
    ngx_pfree(soacf->pool, prop);
  }

  return NGX_OK;
}


static ngx_int_t
ngx_rtmp_sharedobject_remove(ngx_rtmp_session_t *s,
                             ngx_rtmp_sharedobject_t *so,
                             u_char *name, uint32_t len)
{
  ngx_rtmp_header_t            h;

  static uint32_t              zero   = 0;
  static uint32_t              remove = NGX_RTMP_SHARED_REMOVE;
  static ngx_rtmp_amf_elt_t    out_elts[] = {
    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &zero, 0 },

    { NGX_RTMP_AMF_INT8 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &remove, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0},

    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0}
  };

  out_elts[0].data = so->name;
  out_elts[1].data = &(so->version);
  out_elts[2].data = (uint32_t[]){(so->persistent) ? 34 : 0};
  out_elts[5].data = (uint32_t[]){2+len};
  out_elts[6].data = name;
  out_elts[6].len  = len;

  ngx_memzero(&h, sizeof(h));
  h.type = NGX_RTMP_MSG_AMF_SHARED;
  h.csid = NGX_RTMP_CSID_SHARED;

  return (ngx_rtmp_send_amf(s, &h, out_elts,
                            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    ? NGX_ERROR
    : NGX_OK;
}


/*************************************************************************/
static ngx_int_t
ngx_rtmp_sharedobject_clear(ngx_rtmp_session_t *s, ngx_rtmp_sharedobject_t *so)
{
  ngx_rtmp_sharedobject_prop_t *prop;
  ngx_rtmp_header_t             h;

  static uint32_t               zero  = 0;
  static uint32_t               clear = NGX_RTMP_SHARED_CLEAR;
  static ngx_rtmp_amf_elt_t     out_elts[] = {
    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &zero, 0 },

    { NGX_RTMP_AMF_INT8 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &clear, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      &zero, 0 },
  };

  out_elts[0].data = so->name;
  out_elts[1].data = &(so->version);
  out_elts[2].data = (uint32_t[]){(so->persistent) ? 34 : 0};

  ngx_memzero(&h, sizeof(h));
  h.type = NGX_RTMP_MSG_AMF_SHARED;
  h.csid = NGX_RTMP_CSID_SHARED;
  h.msid = 0;

  return (ngx_rtmp_send_amf(s, &h, out_elts,
                            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK)
    ? NGX_ERROR
    : NGX_OK;
}

/*************************************************************************/
static char *
ngx_rtmp_sharedobject_message_type(u_char evt)
{
  static char* evts[] = {
    "?",
    "use",
    "release",
    "request_change",
    "change",
    "success",
    "send_message",
    "status",
    "clear",
    "remove",
    "request_remove",
    "use_success"
  };

  return evt < sizeof(evts) / sizeof(evts[0])
    ? evts[evt]
    : "?";
}


static ngx_int_t
ngx_rtmp_sharedobject_event(ngx_rtmp_session_t *s, u_char *name,
                            uint32_t flags, ngx_chain_t *in)
{
  ngx_rtmp_sharedobject_ctx_t   *ctx;
  ngx_rtmp_sharedobject_t      **so;
  ngx_rtmp_sharedobject_prop_t  *prop;
  ngx_buf_t                     *b;
  u_char                        *p;
  u_char                         evt;
  uint32_t                       len;
  ngx_int_t                      rc = NGX_OK;

  b = in->buf;

  if (b->last - b->pos < 5) {
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "shared-object: too small buffer for event: %d",
                   b->last - b->pos);
    return NGX_ERROR;
  }

  /* read event type */
  evt = b->pos[0];

  /* read event data length */
  p = (u_char*)&len;
  p[0] = b->pos[4];
  p[1] = b->pos[3];
  p[2] = b->pos[2];
  p[3] = b->pos[1];

  ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                 "shared-object: recv evt %s (%d) length=%uD",
                 ngx_rtmp_sharedobject_message_type(evt), (int)evt, len);


  switch (evt) {
      case NGX_RTMP_SHARED_USE:
        /* Skip data */
        b->pos += len + 5;
        so = ngx_rtmp_sharedobject_use(s, name, flags);

        /* Prepare the response */
        if (so == NULL) {
          rc = NGX_ERROR;
        }
        else {
          rc = ngx_rtmp_sharedobject_use_success(s, *so);
          if ((*so)->prop) {
            for (prop = (*so)->prop; rc == NGX_OK && prop; prop = prop->next) {
              rc = ngx_rtmp_sharedobject_change(s, *so, prop);
            }
          }
          else {
            rc = ngx_rtmp_sharedobject_clear(s, *so);
          }
          ngx_rtmp_sharedobject_status(s, *so, "SharedObject.Connect.Success",
                                       "status");
          for (ctx = (*so)->ctx; ctx; ctx = ctx->next) {
            if (ctx->session != s) {
              ngx_rtmp_sharedobject_status(ctx->session, *so,
                                           "SharedObject.Peer.Connect",
                                           "status");
            }
          }
        }
        break;

      case NGX_RTMP_SHARED_RELEASE:
        /* Skip event data */
        b->pos += len + 5;
        so = ngx_rtmp_sharedobject_get(s, name);
        if (so == NULL) {
          rc = NGX_ERROR;
        }
        else {
          ngx_rtmp_sharedobject_status(s, *so, "SharedObject.Connect.Closed",
                                       "status");
          for (ctx = (*so)->ctx; ctx; ctx = ctx->next) {
            if (ctx->session != s) {
              ngx_rtmp_sharedobject_status(ctx->session, *so,
                                           "SharedObject.Peer.Disconnect",
                                           "status");
            }
          }
          rc = ngx_rtmp_sharedobject_release(s, *so);
        }
        break;

      case NGX_RTMP_SHARED_REQUEST_CHANGE:
        {
          u_char data[len];

          /* Read data */
          ngx_memcpy(data, b->pos + 5, len);
          b->pos += len + 5;

          so = ngx_rtmp_sharedobject_get(s, name);
          if (so == NULL) {
            rc = NGX_ERROR;
          }
          else {
            prop = ngx_rtmp_sharedobject_request_change(s, *so, data, len);
            if (prop == NULL) {
              rc = NGX_ERROR;
            }
            else {
              rc = ngx_rtmp_sharedobject_success(s, *so, prop->name,
                                                 prop->name_len);
              (*so)->version += 1;
              for (ctx = (*so)->ctx; rc == NGX_OK && ctx; ctx = ctx->next) {
                if (ctx->session != s) {
                  rc = ngx_rtmp_sharedobject_change(ctx->session, *so, prop);
                }
              }
            }
          }
        }
        break;

      case NGX_RTMP_SHARED_SEND_MESSAGE:
        {
          u_char data[len];

          /* Read data */
          ngx_memcpy(data, b->pos + 5, len);
          b->pos += len + 5;

          so = ngx_rtmp_sharedobject_get(s, name);
          if (so != NULL) {
            rc = ngx_rtmp_sharedobject_sendmsg(s, *so, data, len);
          }
        }
        break;

      case NGX_RTMP_SHARED_REQUEST_REMOVE:
        {
          u_char data[len];

          /* Read data */
          ngx_memcpy(data, b->pos + 5, len);
          b->pos += len + 5;

          so = ngx_rtmp_sharedobject_get(s, name);
          if (so != NULL) {
            rc = ngx_rtmp_sharedobject_request_remove(s, *so, data+2, len-2);
            if (rc != NGX_ERROR) {
              rc = ngx_rtmp_sharedobject_success(s, *so, data+2, len-2);
              (*so)->version += 1;
              for (ctx = (*so)->ctx; rc == NGX_OK && ctx; ctx = ctx->next) {
                if (ctx->session != s) {
                  rc = ngx_rtmp_sharedobject_remove(ctx->session, *so,
                                                    data+2, len-2);
                }
              }
            }
          }
        }
        break;

      default:
        /* Ignore event and skip data */
        b->pos += len + 5;
        break;
  }

  return rc;
}



static ngx_int_t
ngx_rtmp_sharedobject_message_handler(ngx_rtmp_session_t *s,
                                      ngx_rtmp_header_t *h,
                                      ngx_chain_t *in)
{
  ngx_rtmp_amf_ctx_t            act;

  static u_char                 name[NGX_RTMP_MAX_NAME];
  static uint32_t               version;
  static uint32_t               flags;

  static ngx_rtmp_amf_elt_t     in_elts[] = {
    { NGX_RTMP_AMF_STRING | NGX_RTMP_AMF_TYPELESS,
      ngx_string("name"),
      name, sizeof(name) },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_string("version"),
      &version, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_string("flags"),
      &flags, 0 },

    { NGX_RTMP_AMF_INT32 | NGX_RTMP_AMF_TYPELESS,
      ngx_null_string,
      NULL, 0 },
  };

  if (h->type == NGX_RTMP_MSG_AMF3_SHARED) {
    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "AMF3 prefix: %ui", (ngx_int_t)*in->buf->pos);
    ++in->buf->pos;
  }

  ngx_memzero(&act, sizeof(act));
  act.link = in;
  act.log = s->connection->log;
  memset(name, 0, sizeof(name));

  if (ngx_rtmp_amf_read(&act, in_elts,
                        sizeof(in_elts) / sizeof(in_elts[0])) != NGX_OK) {
    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "shared-object: invalid message");
    return NGX_ERROR;
  }

  ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                 "shared-object: name=%s persistent=%s timestamp=%uD",
                 name, ((flags == 0) ? "false" : "true"), h->timestamp);

  in = act.link;
  in->buf->pos += act.offset;

  while (in->buf->pos != in->buf->last) {
    if (ngx_rtmp_sharedobject_event(s, name, flags, in) != NGX_OK) {
      ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                     "shared-object: invalid event");
      return NGX_ERROR;
    }
  }

  return NGX_DONE;
}



/*************************************************************************/
static ngx_int_t
ngx_rtmp_sharedobject_disconnect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                                  ngx_chain_t *in)
{
  ngx_rtmp_sharedobject_ctx_t           *ctx, *p;

  ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_sharedobject_module);
  if (ctx == NULL) {
    return NGX_OK;
  }

  while (ctx->shared_objects) {
    ngx_rtmp_sharedobject_status(s, ctx->shared_objects->shared_object,
                                 "SharedObject.Connect.Closed",
                                 "status");
    for (p = ctx->shared_objects->shared_object->ctx; p; p = p->next) {
      if (p->session != s) {
        ngx_rtmp_sharedobject_status(p->session,
                                     ctx->shared_objects->shared_object,
                                     "SharedObject.Peer.Disconnect",
                                     "status");
      }
    }
    ngx_rtmp_sharedobject_release(s, ctx->shared_objects->shared_object);
  }

  return NGX_OK;
}


static ngx_int_t
ngx_rtmp_sharedobject_postconfiguration(ngx_conf_t *cf)
{
  ngx_rtmp_core_main_conf_t     *cmcf;
  ngx_rtmp_handler_pt           *h;

  cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

  /* register raw event handlers */
  h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AMF_SHARED]);
  *h = ngx_rtmp_sharedobject_message_handler;

  h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AMF3_SHARED]);
  *h = ngx_rtmp_sharedobject_message_handler;

  h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
  *h = ngx_rtmp_sharedobject_disconnect;

  return NGX_OK;
}
