_rotbyte() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--check --report --accept --accept-all --import --workers --quiet --skip-missing --include-hidden --exclude --db --version --help"

    case "$prev" in
        --accept|--db)
            COMPREPLY=($(compgen -f -- "$cur"))
            return 0
            ;;
        --workers)
            COMPREPLY=($(compgen -W "1 2 4 8 16" -- "$cur"))
            return 0
            ;;
        --exclude)
            COMPREPLY=($(compgen -d -- "$cur"))
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
    else
        COMPREPLY=($(compgen -d -- "$cur"))
    fi
}

complete -F _rotbyte rotbyte