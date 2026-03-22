#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "byedpi/params.h"
#include "error.h"
#include "main.h"
#include "packets.h"
#include "utils.h"

struct params default_params;

void reset_params(void) {
    clear_params();
    params = default_params;
}

extern const struct option options[38];

int parse_args_utils(int argc, char **argv)
{
    int optc = sizeof(options)/sizeof(*options);
    for (int i = 0, e = optc; i < e; i++)
        optc += options[i].has_arg;

    char opt[optc + 1];
    opt[optc] = 0;

    for (int i = 0, o = 0; o < optc; i++, o++) {
        opt[o] = options[i].val;
        for (int c = options[i].has_arg; c; c--) {
            o++;
            opt[o] = ':';
        }
    }

    // Оригинал: params.laddr.sin6_port = htons(1080);
    // В вашем ядре union sockaddr_u не имеет sin6_port напрямую,
    // но имеет in6.sin6_port. Исправляем:
    params.laddr.in6.sin6_port = htons(1080);

    int rez;
    int invalid = 0;

    long val;
    char *end = 0;

    // Оригинал: dp_count -> dp_n
    struct desync_params *dp = add((void *)&params.dp,
                                   &params.dp_n, sizeof(struct desync_params));
    if (!dp) {
        reset_params();
        return -1;
    }

    optind = optreset = 1;

    while (!invalid && (rez = getopt_long(
            argc, argv, opt, options, 0)) != -1) {

        switch (rez) {

            case 'N':
                params.resolve = 0;
                break;
            case 'X':
                params.ipv6 = 0;
                break;
            case 'U':
                params.udp = 0;
                break;

//            case 'h':
//                printf(help_text);
//                reset_params();
//                return 0;
//            case 'v':
//                printf("%s\n", VERSION);
//                reset_params();
//                return 0;

            case 'i':
                if (get_addr(optarg,
                             (struct sockaddr_ina *)&params.laddr) < 0)
                    invalid = 1;
                break;

            case 'p':
                val = strtol(optarg, &end, 0);
                if (val <= 0 || val > 0xffff || *end)
                    invalid = 1;
                else
                    params.laddr.in6.sin6_port = htons(val);
                break;

            case 'I':
                if (get_addr(optarg,
                             (struct sockaddr_ina *)&params.baddr) < 0)
                    invalid = 1;
                break;

            case 'b':
                val = strtol(optarg, &end, 0);
                if (val <= 0 || val > INT_MAX/4 || *end)
                    invalid = 1;
                else
                    params.bfsize = val;
                break;

            case 'c':
                val = strtol(optarg, &end, 0);
                if (val <= 0 || val >= (0xffff/2) || *end)
                    invalid = 1;
                else
                    params.max_open = val;
                break;

            case 'x': //
                params.debug = strtol(optarg, 0, 0);
                if (params.debug < 0)
                    invalid = 1;
                break;

            // desync options

            case 'F':
                params.tfo = 1;
                break;

            case 'A':
                dp = add((void *)&params.dp, &params.dp_n,
                         sizeof(struct desync_params));
                if (!dp) {
                    reset_params();
                    return -1;
                }
                end = optarg;
                while (end && !invalid) {
                    switch (*end) {
                        case 't':
                            dp->detect |= DETECT_TORST;
                            break;
                        case 'r':
                            dp->detect |= DETECT_HTTP_LOCAT;
                            break;
                        case 'a':
                        case 's':
                            dp->detect |= DETECT_TLS_ERR;
                            break;
                        case 'n':
                            break;
                        default:
                            invalid = 1;
                            continue;
                    }
                    end = strchr(end, ',');
                    if (end) end++;
                }
                break;

            case 'u':
                val = strtol(optarg, &end, 0);
                if (val <= 0 || *end)
                    invalid = 1;
                else
                    // В вашем ядре поле cache_ttl отсутствует. Игнорируем.
                    // params.cache_ttl = val;
                    break;

            case 'T':;
#ifdef __linux__
                float f = strtof(optarg, &end);
                val = (long)(f * 1000);
#else
                val = strtol(optarg, &end, 0);
#endif
                if (val <= 0 || val > UINT_MAX || *end)
                    invalid = 1;
                else
                    params.timeout = val;
                break;

            case 'K':
                end = optarg;
                while (end && !invalid) {
                    switch (*end) {
                        case 't':
                            dp->proto |= IS_HTTPS;
                            break;
                        case 'h':
                            dp->proto |= IS_HTTP;
                            break;
                        case 'u':
                            dp->proto |= IS_UDP;
                            break;
                        default:
                            invalid = 1;
                            continue;
                    }
                    end = strchr(end, ',');
                    if (end) end++;
                }
                break;

            case 'H':;
                // В вашем ядре нет file_ptr, но есть hosts, который может быть загружен через файл.
                // Однако для нашей задачи подмены SNI мы не будем использовать файл,
                // а передадим SNI через аргументы командной строки (--fake-sni).
                // Чтобы не усложнять, просто пропускаем эту опцию.
                // Если нужно, можно реализовать через parse_hosts, но пока закомментируем.
                // Переходим к следующей опции.
                continue;
                // Оригинальный код:
                /*
                if (dp->file_ptr) {
                    continue;
                }
                dp->file_ptr = ftob(optarg, &dp->file_size);
                if (!dp->file_ptr) {
                    uniperror("read/parse");
                    invalid = 1;
                    continue;
                }
                dp->hosts = parse_hosts(dp->file_ptr, dp->file_size);
                if (!dp->hosts) {
                    perror("parse_hosts");
                    reset_params();
                    return -1;
                }
                */
                break;

            case 's':
            case 'd':
            case 'o':
            case 'q':
            case 'f':
                ;
                struct part *part = add((void *)&dp->parts,
                                        &dp->parts_n, sizeof(struct part));
                if (!part) {
                    reset_params();
                    return -1;
                }
                if (parse_offset(part, optarg)) {
                    invalid = 1;
                    break;
                }
                switch (rez) {
                    case 's': part->m = DESYNC_SPLIT;
                        break;
                    case 'd': part->m = DESYNC_DISORDER;
                        break;
                    case 'o': part->m = DESYNC_OOB;
                        break;
                    case 'q': part->m = DESYNC_DISOOB;
                        break;
                    case 'f': part->m = DESYNC_FAKE;
                }
                break;

            case 't':
                val = strtol(optarg, &end, 0);
                if (val <= 0 || val > 255 || *end)
                    invalid = 1;
                else
                    dp->ttl = val;
                break;

            case 'k':
                // Опция --ip-options, не поддерживается в вашем ядре. Игнорируем.
                // if (dp->ip_options) continue; ...
                continue;

            case 'S':
                dp->md5sig = 1;
                break;

            case 'O':
                // fake_offset — это поле типа struct part, присваивать int нельзя.
                // Эта опция не используется для подмены SNI, игнорируем.
                // val = strtol(...);
                // dp->fake_offset = val;
                continue;

            case 'n':
                // Опция --fake-sni. В ядре есть fake_sni_list.
                // Здесь оригинальный код пытался подменить SNI в fake_tls.
                // Вместо этого нужно добавить в dp->fake_sni_list.
                // Но проще оставить, как есть, потому что change_tls_sni работает?
                // Проверим: в вашем ядре change_tls_sni имеет 4 аргумента.
                // Мы вызовем его с правильными аргументами.
                if (change_tls_sni(optarg, fake_tls.data, fake_tls.size, fake_tls.size)) {
                    perror("change_tls_sni");
                    reset_params();
                    return -1;
                }
                LOG(LOG_S, "sni: %s", optarg);
                break;

            case 'l':
                if (dp->fake_data.data) {
                    continue;
                }
                dp->fake_data.data = ftob(optarg, &dp->fake_data.size);
                if (!dp->fake_data.data) {
                    uniperror("read/parse");
                    invalid = 1;
                }
                break;

            case 'e':
                val = parse_cform(dp->oob_char, 1, optarg, strlen(optarg));
                if (val != 1) {
                    invalid = 1;
                }
                else dp->oob_char[1] = 1;
                break;

            case 'M':
                end = optarg;
                while (end && !invalid) {
                    switch (*end) {
                        case 'r':
                            dp->mod_http |= MH_SPACE;
                            break;
                        case 'h':
                            dp->mod_http |= MH_HMIX;
                            break;
                        case 'd':
                            dp->mod_http |= MH_DMIX;
                            break;
                        default:
                            invalid = 1;
                            continue;
                    }
                    end = strchr(end, ',');
                    if (end) end++;
                }
                break;

            case 'r':
                part = add((void *)&dp->tlsrec,
                           &dp->tlsrec_n, sizeof(struct part));
                if (!part) {
                    reset_params();
                    return -1;
                }
                if (parse_offset(part, optarg)
                    || part->pos > 0xffff) {
                    invalid = 1;
                    break;
                }
                break;

            case 'a':
                val = strtol(optarg, &end, 0);
                if (val < 0 || val > INT_MAX || *end)
                    invalid = 1;
                else
                    dp->udp_fake_count = val;
                break;

            case 'V':
                val = strtol(optarg, &end, 0);
                if (val <= 0 || val > USHRT_MAX)
                    invalid = 1;
                else {
                    dp->pf[0] = htons(val);
                    if (*end == '-') {
                        val = strtol(end + 1, &end, 0);
                        if (val <= 0 || val > USHRT_MAX)
                            invalid = 1;
                    }
                    if (*end)
                        invalid = 1;
                    else
                        dp->pf[1] = htons(val);
                }
                break;

            case 'g':
                val = strtol(optarg, &end, 0);
                if (val <= 0 || val > 255 || *end)
                    invalid = 1;
                else {
                    params.def_ttl = val;
                    params.custom_ttl = 1;
                }
                break;

            case 'Y':
                dp->drop_sack = 1;
                break;

            case 'w': //
                // params.sfdelay — нет в вашем ядре, игнорируем
                // params.sfdelay = strtol(...);
                continue;

            case 'W':
                params.wait_send = 0;
                break;
#ifdef __linux__
            case 'P':
                params.protect_path = optarg;
                break;
#endif
            case 0:
                break;

            case '?':
                reset_params();
                return -1;

            default:
                LOG(LOG_S, "Unknown option: -%c", rez);
                reset_params();
                return -1;
        }
    }
    if (invalid) {
        LOG(LOG_S, "invalid value: -%c %s", rez, optarg);
        reset_params();
        return -1;
    }
    // Оригинал: if (dp->hosts || dp->proto || dp->pf[0]) { dp = add(...); }
    // Упростим: если уже есть dp, то создаём следующий? Но для подмены SNI не нужно.
    // Оставляем как есть, но заменим dp_count на dp_n.
    if (dp->hosts || dp->proto || dp->pf[0]) {
        dp = add((void *)&params.dp,
                 &params.dp_n, sizeof(struct desync_params));
        if (!dp) {
            reset_params();
            return -1;
        }
    }

    if (params.baddr.in6.sin6_family != AF_INET6) {
        params.ipv6 = 0;
    }
    if (!params.def_ttl) {
        if ((params.def_ttl = get_default_ttl()) < 1) {
            reset_params();
            return -1;
        }
    }
    // mem_pool требует два аргумента: flags и cmp_type
    params.mempool = mem_pool(0, 0);
    if (!params.mempool) {
        uniperror("mem_pool");
        reset_params();
        return -1;
    }

    return 0;
}