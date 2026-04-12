_rotbyte() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--check --report --accept --accept-all --import --workers --quiet --skip-missing --include-hidden --exclude --db --export --json --budget --due --track --status --untrack --untrack-all --every --full-at --notify --notify-setup --version --help"

    case "$prev" in
        --accept|--db|--export)
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
        --budget|--every)
            COMPREPLY=($(compgen -W "30m 1h 2h 4h 1h30m 2h30m" -- "$cur"))
            return 0
            ;;
        --full-at)
            COMPREPLY=($(compgen -W "0h 1h 2h 3h 4h 6h 12h 14h 18h 22h" -- "$cur"))
            return 0
            ;;
        --due)
            COMPREPLY=($(compgen -W "7d 14d 30d 60d 90d" -- "$cur"))
            return 0
            ;;
        --notify|--notify-setup)
            COMPREPLY=($(compgen -W "email" -- "$cur"))
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