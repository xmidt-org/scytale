#!/usr/bin/env sh
set -e

# check arguments for an option that would cause /scytale to stop
# return true if there is one
_want_help() {
    local arg
    for arg; do
        case "$arg" in
            -'?'|--help|-v)
                return 0
                ;;
        esac
    done
    return 1
}

_main() {
    # if command starts with an option, prepend scytale
    if [ "${1:0:1}" = '-' ]; then
        set -- /scytale "$@"
    fi

    # skip setup if they aren't running /scytale or want an option that stops /scytale
    if [ "$1" = '/scytale' ] && ! _want_help "$@"; then
        echo "Entrypoint script for scytale Server ${VERSION} started."

        if [ ! -s /etc/scytale/scytale.yaml ]; then
            echo "Building out template for file"
            /bin/spruce merge /tmp/scytale_spruce.yaml > /etc/scytale/scytale.yaml
        fi
    fi

    exec "$@"
}

_main "$@"
