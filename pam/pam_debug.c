#include <stdlib.h>
#include <syslog.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>

#define KEETO_SYSLOG_IDENTIFIER "sshd"
#define LOG_FACILITY LOG_LOCAL0

#ifdef UNSUPPORTED_POSIX_THREADS_HACK                                            

#include <pthread.h>                                                             
typedef pthread_t sp_pthread_t;                                                      

#else                                                                            
typedef pid_t sp_pthread_t;                                                                                                                                                                                                                    
#endif 

struct pam_ctxt {
    sp_pthread_t pam_thread;
    int pam_psock;
    int pam_csock;
    int pam_done;
};

static void
get_environment(pam_handle_t *pamh)
{
    syslog(LOG_INFO, "PAM_GET_ENVIRONMENT()");
    char **env = pam_getenvlist(pamh);
    if (env == NULL) {
        syslog(LOG_ERR, "pam_getenvlist() failed");
        return;
    }
    syslog(LOG_INFO, "ENVIRONMENT:");
    for (int i = 0; env[i] != NULL; i++) {
        syslog(LOG_INFO, "%s", env[i]);
    }
}

static void
get_pam_data(pam_handle_t *pamh)
{
    syslog(LOG_INFO, "PAM_GET_DATA()");
    char *pam_data_value = NULL;
    int rc = pam_get_data(pamh, "my_own_pam_data", (const void **)&pam_data_value);
    if (rc != PAM_SUCCESS) {
        syslog(LOG_ERR, "failed to get pam data");
    }
    syslog(LOG_INFO, "my_own_pam_data: %s", pam_data_value);
}

static void
get_pam_items(pam_handle_t *pamh)
{
    syslog(LOG_INFO, "PAM_GET_ITEM()");
    const void *item = NULL;
    int rc = pam_get_item(pamh, PAM_SERVICE, &item);
    if (rc == PAM_SUCCESS) {
        syslog(LOG_INFO, "PAM_SERVICE: %s", (const char *)item);
    }
    rc = pam_get_item(pamh, PAM_USER, &item);
    if (rc == PAM_SUCCESS) {
        syslog(LOG_INFO, "PAM_USER: %s", (const char *)item);
    }
    rc = pam_get_item(pamh, PAM_USER_PROMPT, &item);
    if (rc == PAM_SUCCESS) {
        syslog(LOG_INFO, "PAM_USER_PROMPT: %s", (const char *)item);
    }
    rc = pam_get_item(pamh, PAM_TTY, &item);
    if (rc == PAM_SUCCESS) {
        syslog(LOG_INFO, "PAM_TTY: %s", (const char *)item);
    }
    rc = pam_get_item(pamh, PAM_RUSER, &item);
    if (rc == PAM_SUCCESS) {
        syslog(LOG_INFO, "PAM_RUSER: %s", (const char *)item);
    }
    rc = pam_get_item(pamh, PAM_RHOST, &item);
    if (rc == PAM_SUCCESS) {
        syslog(LOG_INFO, "PAM_RHOST: %s", (const char *)item);
    }
    rc = pam_get_item(pamh, PAM_AUTHTOK, &item);
    if (rc == PAM_SUCCESS) {
        syslog(LOG_INFO, "PAM_AUTHTOK: %s", (const char *)item);
    }
    rc = pam_get_item(pamh, PAM_OLDAUTHTOK, &item);
    if (rc == PAM_SUCCESS) {
        syslog(LOG_INFO, "PAM_OLDAUTHTOK %s", (const char *)item);
    }
}

static void
cleanup(pam_handle_t *pamh, void *data, int error_status)
{
    syslog(LOG_INFO, "cleanup()");
}

/*
 * authentication management
 */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    openlog(KEETO_SYSLOG_IDENTIFIER, LOG_PID, LOG_FACILITY);
    syslog(LOG_INFO, "pam_sm_authenticate()");
    syslog(LOG_INFO, "setting environment variable");
    int rc = pam_putenv(pamh, "my_own_env_var=foo");
    if (rc != PAM_SUCCESS) {
        syslog(LOG_ERR, "pam_putenv() (%s)", pam_strerror(pamh, rc));
    }
    syslog(LOG_INFO, "setting pam data");
    char *pam_data_value = "foo";
    rc = pam_set_data(pamh, "my_own_pam_data", pam_data_value, &cleanup);
    if (rc != PAM_SUCCESS) {
        syslog(LOG_ERR, "pam_set_data()");
        return PAM_SYSTEM_ERR;
    }
    get_environment(pamh);
    get_pam_data(pamh);
    get_pam_items(pamh);
    /* get conversation function */
    const struct pam_conv *pam_conv = NULL;
    rc = pam_get_item(pamh, PAM_CONV, (const void **)&pam_conv);
    if (rc != PAM_SUCCESS) {
        return PAM_SYSTEM_ERR;
    }
    struct pam_ctxt *sshd_auth_ctx = pam_conv->appdata_ptr;
    syslog(LOG_INFO, "PAM_CONV");
    syslog(LOG_INFO, "pid: %d", sshd_auth_ctx->pam_thread);
    syslog(LOG_INFO, "psock: %d", sshd_auth_ctx->pam_psock);
    syslog(LOG_INFO, "csock: %d", sshd_auth_ctx->pam_csock);
    syslog(LOG_INFO, "done: %d", sshd_auth_ctx->pam_done);

    /* call conversation function */
    struct pam_message request1 = {
        .msg_style = PAM_PROMPT_ECHO_ON,
        .msg = "Reason: "
    };
    struct pam_message request2 = {
        .msg_style = PAM_PROMPT_ECHO_ON,
        .msg = "Ticket number required: "
    };
    const struct pam_message *requests[] = {
        &request1,
        &request2
    };
    struct pam_response *responses = NULL;
    int amount_requests = sizeof requests / sizeof *requests;
    syslog(LOG_INFO, "requests: %d", amount_requests);
    rc = pam_conv->conv(amount_requests, requests,
        &responses, pam_conv->appdata_ptr);
    if (rc != PAM_SUCCESS) {
        return PAM_SYSTEM_ERR;
    }
    for (int i = 0; i < amount_requests; i++) {
        syslog(LOG_INFO, "Response: %s (%d)", responses[i].resp,
            responses[i].resp_retcode);
    }

    closelog();
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    openlog(KEETO_SYSLOG_IDENTIFIER, LOG_PID, LOG_FACILITY);
    syslog(LOG_INFO, "pam_sm_setcred()");
    get_environment(pamh);
    get_pam_data(pamh);
    get_pam_items(pamh);
    closelog();
    return PAM_SUCCESS;
}

/*
 * account management
 */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    openlog(KEETO_SYSLOG_IDENTIFIER, LOG_PID, LOG_FACILITY);
    syslog(LOG_INFO, "pam_sm_acct_mgmt()");
    get_environment(pamh);
    get_pam_data(pamh);
    get_pam_items(pamh);
    closelog();
    return PAM_SUCCESS;
}

/*
 * session management
 */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    openlog(KEETO_SYSLOG_IDENTIFIER, LOG_PID, LOG_FACILITY);
    syslog(LOG_INFO, "pam_sm_open_session()");
    get_environment(pamh);
    get_pam_data(pamh);
    get_pam_items(pamh);
    closelog();
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    openlog(KEETO_SYSLOG_IDENTIFIER, LOG_PID, LOG_FACILITY);
    syslog(LOG_INFO, "pam_sm_close_session()");
    get_environment(pamh);
    get_pam_data(pamh);
    get_pam_items(pamh);
    closelog();
    return PAM_SUCCESS;
}

/*
 * authentication token management
 */
PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    openlog(KEETO_SYSLOG_IDENTIFIER, LOG_PID, LOG_FACILITY);
    syslog(LOG_INFO, "pam_sm_chauthtok()");
    get_environment(pamh);
    get_pam_data(pamh);
    get_pam_items(pamh);
    closelog();
    return PAM_SUCCESS;
}

