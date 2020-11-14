/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "cryptsetup-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "terminal-util.h"

static char *arg_root_hash = NULL;
static char *arg_data_what = NULL;
static char *arg_hash_what = NULL;
static uint64_t arg_hash_offset = 0;
static bool arg_no_superblock = false;
static bool arg_ignore_corruption = false;
static bool arg_restart_on_corruption = false;
static bool arg_panic_on_corruption = false;
static bool arg_ignore_zero_blocks = false;
static bool arg_check_at_most_once = false;

STATIC_DESTRUCTOR_REGISTER(arg_root_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_data_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_hash_what, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-veritysetup@.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s attach VOLUME DATADEVICE HASHDEVICE ROOTHASH [ROOTHASHSIG] [OPTIONS]\n"
               "%s detach VOLUME\n\n"
               "Attaches or detaches an integrity protected block device.\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_HASH_OFFSET,
                ARG_NO_SUPERBLOCK,
                ARG_IGNORE_CORRUPTION,
                ARG_RESTART_ON_CORRUPTION,
                ARG_PANIC_ON_CORRUPTION,
                ARG_IGNORE_ZERO_BLOCKS,
                ARG_CHECK_AT_MOST_ONCE,
                ARG_ROOT_HASH_SIGNATURE,
        };

        static const struct option options[] = {
                { "help",                  no_argument,       NULL, 'h'               },
                { "version",               no_argument,       NULL, ARG_VERSION       },
                { "hash-offset",           required_argument, NULL, ARG_HASH_OFFSET   },
                { "no-superblock",         required_argument, NULL, ARG_NO_SUPERBLOCK },
                { "ignore-corruption",     required_argument, NULL, ARG_IGNORE_CORRUPTION     },
                { "restart-on-corruption", required_argument, NULL, ARG_RESTART_ON_CORRUPTION },
                { "panic-on-corruption",   required_argument, NULL, ARG_PANIC_ON_CORRUPTION   },
                { "ignore-zero-blocks",    required_argument, NULL, ARG_IGNORE_ZERO_BLOCKS    },
                { "check-at-most-once",    required_argument, NULL, ARG_CHECK_AT_MOST_ONCE    },
                { "root-hash-signature",   required_argument, NULL, ARG_ROOT_HASH_SIGNATURE   },
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_HASH_OFFSET:
                        r = safe_atou64(optarg, &arg_hash_offset);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --hash-offset: %s", optarg);

                        break;

                case ARG_NO_SUPERBLOCK:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Failed to parse --no-superblock= argument.");

                                arg_no_superblock = r;
                        } else
                                arg_no_superblock = true;

                        break;

                case ARG_IGNORE_CORRUPTION:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Failed to parse --ignore-corruption= argument.");

                                arg_ignore_corruption = r;
                        } else
                                arg_ignore_corruption = true;

                        break;

                case ARG_RESTART_ON_CORRUPTION:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Failed to parse --restart-on-corruption= argument.");

                                arg_restart_on_corruption = r;
                        } else
                                arg_restart_on_corruption = true;

                        break;

                case ARG_PANIC_ON_CORRUPTION:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Failed to parse --panic-on-corruption= argument.");

                                arg_panic_on_corruption = r;
                        } else
                                arg_panic_on_corruption = true;

                        break;

                case ARG_IGNORE_ZERO_BLOCKS:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Failed to parse --ignore-zero-blocks= argument.");

                                arg_ignore_zero_blocks = r;
                        } else
                                arg_ignore_zero_blocks = true;

                        break;

                case ARG_CHECK_AT_MOST_ONCE:
                        if (optarg) {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Failed to parse --check-at-most-once= argument.");

                                arg_check_at_most_once = r;
                        } else
                                arg_check_at_most_once = true;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option code.");
                }

        return 1;
}

static int run(int argc, char *argv[]) {
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        int r;

        if (argc <= 1)
                return help();

        if (argc < 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program requires at least two arguments.");

        log_setup_service();

        umask(0022);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (streq(argv[1], "attach")) {
                uint32_t flags = CRYPT_ACTIVATE_READONLY;
                _cleanup_free_ void *m = NULL;
                crypt_status_info status;
                size_t l;

                if (argc < 6)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "attach requires at least two arguments.");

                r = unhexmem(argv[5], strlen(argv[5]), &m, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse root hash: %m");

                r = crypt_init(&cd, argv[4]);
                if (r < 0)
                        return log_error_errno(r, "Failed to open verity device %s: %m", argv[4]);

                cryptsetup_enable_logging(cd);

                status = crypt_status(cd, argv[2]);
                if (IN_SET(status, CRYPT_ACTIVE, CRYPT_BUSY)) {
                        log_info("Volume %s already active.", argv[2]);
                        return 0;
                }

                if (arg_ignore_corruption)
                        flags |= CRYPT_ACTIVATE_IGNORE_CORRUPTION;
                if (arg_restart_on_corruption)
                       flags |= CRYPT_ACTIVATE_RESTART_ON_CORRUPTION;
                if (arg_ignore_zero_blocks)
                        flags |= CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS;
#ifdef CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE
                if (arg_check_at_most_once)
                        flags |= CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE;
#endif
#ifdef CRYPT_ACTIVATE_PANIC_ON_CORRUPTION
                if (arg_panic_on_corruption)
                        flags |= CRYPT_ACTIVATE_PANIC_ON_CORRUPTION;
#endif

                r = crypt_load(cd, CRYPT_VERITY, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to load verity superblock: %m");

                r = crypt_set_data_device(cd, argv[3]);
                if (r < 0)
                        return log_error_errno(r, "Failed to configure data device: %m");

                if (argc > 6 && !streq(argv[6], "-")) {
#if HAVE_CRYPT_ACTIVATE_BY_SIGNED_KEY
                        _cleanup_free_ char *hash_sig = NULL;
                        size_t hash_sig_size;
                        char *value;

                        if ((value = startswith(argv[6], "base64:"))) {
                                r = unbase64mem(value, strlen(value), (void *)&hash_sig, &hash_sig_size);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse root hash signature '%s': %m", argv[6]);
                        } else {
                                r = read_full_file_full(AT_FDCWD, argv[6], READ_FULL_FILE_CONNECT_SOCKET, NULL, &hash_sig, &hash_sig_size);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to read root hash signature: %m");
                        }

                        r = crypt_activate_by_signed_key(cd, argv[2], m, l, hash_sig, hash_sig_size, flags);
#else
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "activation of verity device with signature %s requested, but not supported by cryptsetup due to missing crypt_activate_by_signed_key()", argv[6]);
#endif
                } else
                        r = crypt_activate_by_volume_key(cd, argv[2], m, l, flags);
                if (r < 0)
                        return log_error_errno(r, "Failed to set up verity device: %m");

        } else if (streq(argv[1], "detach")) {

                r = crypt_init_by_name(&cd, argv[2]);
                if (r == -ENODEV) {
                        log_info("Volume %s already inactive.", argv[2]);
                        return 0;
                }
                if (r < 0)
                        return log_error_errno(r, "crypt_init_by_name() failed: %m");

                cryptsetup_enable_logging(cd);

                r = crypt_deactivate(cd, argv[2]);
                if (r < 0)
                        return log_error_errno(r, "Failed to deactivate: %m");

        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown verb %s.", argv[1]);

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
