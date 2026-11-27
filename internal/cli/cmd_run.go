package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"outsider/internal/proto"
	"outsider/internal/sopsage"
)

func summarizeCommand(argv []string) string {
	joined := strings.Join(argv, " ")
	runes := []rune(joined)
	const maxChars = 240
	if len(runes) <= maxChars {
		return joined
	}
	return string(runes[:maxChars-1]) + "…"
}

func splitAtDoubleDash(args []string) (flagArgs []string, target []string, hasDash bool) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}

func runRun(args []string) int {
	flagArgs, target, hasDash := splitAtDoubleDash(args)

	fs := pflag.NewFlagSet("run", pflag.ContinueOnError)
	var (
		name           string
		reason         string
		timeout        uint32
		sopsFile       string
		sopsKeys       []string
		envSpec        string
		envAll         bool
		useStdin       bool
		stdinTemplate  string
		noStdinNewline bool
		useFile        bool
		fileEnv        string
		fileFormat     string
		useAskpass     bool
		argPlaceholder string
		saveName       bool
	)

	fs.StringVar(&name, "name", "", "Approval name (required in Direct mode; auto-resolved in SOPS mode when registered)")
	fs.StringVar(&reason, "reason", "", "Human-readable reason shown on notification and approval page")
	fs.Uint32Var(&timeout, "timeout", 0, "Approval timeout in seconds")
	fs.StringVar(&sopsFile, "sops", "", "Enable SOPS mode and specify local encrypted YAML file path")
	fs.StringArrayVar(&sopsKeys, "sops-key", nil, "Extract specific SOPS leaf key path (repeatable; e.g. GH_TOKEN or db.password)")
	fs.StringVar(&envSpec, "env", "", "Inject single secret into environment variable (`VAR` or `VAR=prefix_{{secret}}`)")
	fs.BoolVar(&envAll, "env-all", false, "Inject extracted SOPS key(s) directly as environment variables")
	fs.BoolVar(&useStdin, "stdin", false, "Inject single secret into child process stdin via pipe")
	fs.StringVar(&stdinTemplate, "stdin-template", "", "Custom stdin template containing `{{secret}}` (requires --stdin)")
	fs.BoolVar(&noStdinNewline, "no-stdin-newline", false, "Do not append trailing newline when using --stdin")
	fs.BoolVar(&useFile, "file", false, "Write secret(s) to 0600 temp file and replace `{{file}}` in target command")
	fs.StringVar(&fileEnv, "file-env", "", "Write secret(s) to 0600 temp file and pass its path in the given env var")
	fs.StringVar(&fileFormat, "file-format", "dotenv", "Serialization format for multi-key SOPS --file/--file-env: dotenv, yaml, json")
	fs.BoolVar(&useAskpass, "askpass", false, "Provide single secret via SSH_ASKPASS / GIT_ASKPASS / SUDO_ASKPASS (use 'sudo -A' for sudo)")
	fs.StringVar(&argPlaceholder, "arg-placeholder", "", "Replace placeholder in target command arguments (legacy fallback; visible in ps)")
	fs.BoolVar(&saveName, "save-name", false, "Register/verify --name in config.toml after successful approval")

	if err := fs.Parse(flagArgs); err != nil {
		if err == pflag.ErrHelp {
			return 0
		}
		fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
		return ExitConfigOrArg
	}
	if !hasDash || len(target) == 0 {
		fmt.Fprintln(os.Stderr, "[outsider] Argument error: missing target command after `--`")
		return ExitConfigOrArg
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "[outsider] Argument error: unexpected positional arguments before `--`: %v\n", fs.Args())
		return ExitConfigOrArg
	}

	// Resolve mutually exclusive handoff mode.
	spec, err := resolveHandoffSpec(fs, handoffFlags{
		envSpec:        envSpec,
		envAll:         envAll,
		useStdin:       useStdin,
		stdinTemplate:  stdinTemplate,
		noStdinNewline: noStdinNewline,
		useFile:        useFile,
		fileEnv:        fileEnv,
		fileFormat:     fileFormat,
		useAskpass:     useAskpass,
		argPlaceholder: argPlaceholder,
	}, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
		return ExitConfigOrArg
	}

	cfg, id, err := loadConfigAndIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer id.Wipe()

	ttl := cfg.DefaultTimeoutSecs
	if fs.Changed("timeout") && timeout > 0 {
		ttl = timeout
	}

	client := NewRelayClient(cfg.RelayURL)
	ctx := context.Background()

	// === Direct mode ===
	if strings.TrimSpace(sopsFile) == "" {
		if len(sopsKeys) > 0 {
			fmt.Fprintln(os.Stderr, "[outsider] Argument error: --sops-key requires --sops <file>")
			return ExitConfigOrArg
		}
		if fs.Changed("file-format") {
			fmt.Fprintln(os.Stderr, "[outsider] Argument error: --file-format requires --sops <file>")
			return ExitConfigOrArg
		}
		if spec.Kind == HandoffEnvAll {
			fmt.Fprintln(os.Stderr, "[outsider] Argument error: --env-all requires --sops <file>")
			return ExitConfigOrArg
		}
		name = strings.TrimSpace(name)
		if name == "" {
			fmt.Fprintln(os.Stderr, "[outsider] Argument error: --name is required in Direct mode")
			return ExitConfigOrArg
		}
		if saveName {
			slug := proto.SlugifyName(name)
			if existing, ok := cfg.Names[slug]; ok && existing.IsSops() {
				fmt.Fprintf(os.Stderr, "[outsider] Config error: name %q is already registered as a SOPS age key\n", slug)
				return ExitConfigOrArg
			}
		}

		reqCtx := proto.Context{
			Name:           name,
			Reason:         reason,
			CommandSummary: summarizeCommand(target),
		}
		secret, err := client.RequestSecret(ctx, id, reqCtx, ttl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
			return exitCodeOf(err)
		}

		if saveName {
			if err := saveDirectNameIfAbsent(proto.SlugifyName(name), reason); err != nil {
				clear(secret)
				fmt.Fprintf(os.Stderr, "[outsider] Config error: %v\n", err)
				return ExitConfigOrArg
			}
		}

		payload := &HandoffPayload{Single: secret, IsMulti: false}
		code, err := ExecuteTarget(spec, payload, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] Execution error: %v\n", err)
			return code
		}
		return code
	}

	// === SOPS mode (Fail-Fast before calling Relay!) ===
	displayFile := strings.TrimSpace(sopsFile)
	expandedFile, err := ExpandTilde(displayFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Error: %v\n", err)
		return ExitConfigOrArg
	}
	meta, err := sopsage.InspectFile(expandedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] SOPS error: %v\n", err)
		return ExitConfigOrArg
	}

	var targetKeys []string
	if len(sopsKeys) > 0 {
		for _, k := range sopsKeys {
			k = strings.TrimSpace(k)
			if _, err := sopsage.ValidateKeyPath(k); err != nil {
				fmt.Fprintf(os.Stderr, "[outsider] Argument error: %v\n", err)
				return ExitConfigOrArg
			}
			if !meta.KeySet[k] {
				fmt.Fprintf(os.Stderr, "[outsider] SOPS error: key %q not found in %s\n", k, displayFile)
				return ExitConfigOrArg
			}
			targetKeys = append(targetKeys, k)
		}
	} else {
		if len(meta.Keys) == 0 {
			fmt.Fprintf(os.Stderr, "[outsider] SOPS error: %s contains no secret keys\n", displayFile)
			return ExitConfigOrArg
		}
		for _, k := range meta.Keys {
			targetKeys = append(targetKeys, k.Path)
		}
	}

	// Resolve approval name: explicit --name wins, otherwise auto-lookup via sops_recipient.
	approvalName := strings.TrimSpace(name)
	if approvalName == "" {
		resolved, err := cfg.ResolveSopsName(meta.Recipients)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
			return ExitConfigOrArg
		}
		approvalName = resolved
	}
	if saveName {
		slug := proto.SlugifyName(approvalName)
		if existing, ok := cfg.Names[slug]; ok && !existing.IsSops() {
			fmt.Fprintf(os.Stderr, "[outsider] Config error: name %q is already registered as a Direct secret\n", slug)
			return ExitConfigOrArg
		}
	}

	isMulti := len(targetKeys) > 1
	if isMulti {
		switch spec.Kind {
		case HandoffEnvAll, HandoffFile:
			// allowed
		default:
			fmt.Fprintf(os.Stderr, "[outsider] Argument error: %d SOPS keys selected; multi-key mode only supports --env-all, --file, or --file-env\n", len(targetKeys))
			return ExitConfigOrArg
		}
	}
	if spec.Kind == HandoffEnvAll {
		for _, k := range targetKeys {
			if !sopsage.IsValidEnvName(k) {
				fmt.Fprintf(os.Stderr, "[outsider] Argument error: key %q is not a valid POSIX env var name for --env-all (use --file --file-format yaml|json or --sops-key %s --env VAR)\n", k, k)
				return ExitConfigOrArg
			}
		}
	}
	if spec.Kind == HandoffFile && isMulti {
		switch strings.ToLower(strings.TrimSpace(spec.FileFormat)) {
		case "dotenv":
			for _, k := range targetKeys {
				if !sopsage.IsValidEnvName(k) {
					fmt.Fprintf(os.Stderr, "[outsider] Argument error: key %q is not valid for --file-format dotenv (use --file-format yaml or json)\n", k)
					return ExitConfigOrArg
				}
			}
		case "yaml", "json":
		default:
			fmt.Fprintf(os.Stderr, "[outsider] Argument error: unsupported --file-format %q (expected dotenv, yaml, or json)\n", spec.FileFormat)
			return ExitConfigOrArg
		}
	}

	scopeKeys := "*"
	if len(sopsKeys) > 0 {
		scopeKeys = strings.Join(sopsKeys, ",")
	}
	cmdSummary := fmt.Sprintf("[sops:%s keys=%s] %s", displayFile, scopeKeys, summarizeCommand(target))
	reqCtx := proto.Context{
		Name:           approvalName,
		Reason:         reason,
		CommandSummary: cmdSummary,
	}

	ageKey, err := client.RequestSecret(ctx, id, reqCtx, ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
		return exitCodeOf(err)
	}
	defer clear(ageKey)

	// Decrypt in memory, verify MAC, and extract requested keys.
	var selectArg []string
	if len(sopsKeys) > 0 {
		selectArg = targetKeys
	}
	kvs, err := sopsage.Decrypt(expandedFile, ageKey, selectArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] SOPS decrypt error: %v\n", err)
		if errors.Is(err, sopsage.ErrDecrypt) {
			return ExitCrypto
		}
		return ExitConfigOrArg
	}

	if saveName {
		ageID, err := sopsage.ParseAgeIdentity(ageKey)
		if err != nil {
			sopsage.WipeKVs(kvs)
			fmt.Fprintf(os.Stderr, "[outsider] SOPS key error: %v\n", err)
			return ExitCrypto
		}
		recipient := ageID.Recipient().String()
		if err := saveSopsName(proto.SlugifyName(approvalName), recipient, "", false); err != nil {
			sopsage.WipeKVs(kvs)
			fmt.Fprintf(os.Stderr, "[outsider] %v\n", err)
			return exitCodeOf(err)
		}
	}

	// Wipe SOPS_AGE_KEY immediately before handing off to child process.
	clear(ageKey)

	var payload *HandoffPayload
	if !isMulti && len(kvs) == 1 && spec.Kind != HandoffEnvAll {
		val := make([]byte, len(kvs[0].Value))
		copy(val, kvs[0].Value)
		sopsage.WipeKVs(kvs)
		payload = &HandoffPayload{Single: val, IsMulti: false}
	} else if !isMulti && len(kvs) == 1 && spec.Kind == HandoffEnvAll {
		payload = &HandoffPayload{Multi: kvs, IsMulti: false}
	} else {
		payload = &HandoffPayload{Multi: kvs, IsMulti: true}
	}

	code, err := ExecuteTarget(spec, payload, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[outsider] Execution error: %v\n", err)
		return code
	}
	return code
}

type handoffFlags struct {
	envSpec        string
	envAll         bool
	useStdin       bool
	stdinTemplate  string
	noStdinNewline bool
	useFile        bool
	fileEnv        string
	fileFormat     string
	useAskpass     bool
	argPlaceholder string
}

func resolveHandoffSpec(fs *pflag.FlagSet, f handoffFlags, target []string) (HandoffSpec, error) {
	count := 0
	var spec HandoffSpec

	if fs.Changed("env") {
		count++
		spec = HandoffSpec{Kind: HandoffEnv, EnvSpec: f.envSpec}
		if _, _, err := prepareEnvPair(f.envSpec, []byte("x")); err != nil {
			return spec, err
		}
	}
	if f.envAll {
		count++
		spec = HandoffSpec{Kind: HandoffEnvAll}
	}
	if f.useStdin {
		count++
		spec = HandoffSpec{
			Kind:           HandoffStdin,
			StdinTemplate:  f.stdinTemplate,
			HasStdinTmpl:   fs.Changed("stdin-template"),
			NoStdinNewline: f.noStdinNewline,
		}
	} else if fs.Changed("stdin-template") || f.noStdinNewline {
		return spec, errors.New("--stdin-template and --no-stdin-newline require --stdin")
	}
	if f.useFile {
		count++
		hasPlaceholder := false
		for _, a := range target {
			if strings.Contains(a, "{{file}}") {
				hasPlaceholder = true
				break
			}
		}
		if !hasPlaceholder {
			return spec, errors.New("--file requires `{{file}}` placeholder in target command (or use --file-env VAR)")
		}
		spec = HandoffSpec{Kind: HandoffFile, FileFormat: f.fileFormat}
	}
	if fs.Changed("file-env") {
		count++
		if strings.TrimSpace(f.fileEnv) == "" {
			return spec, errors.New("--file-env variable name cannot be empty")
		}
		spec = HandoffSpec{Kind: HandoffFile, FileEnvVar: strings.TrimSpace(f.fileEnv), FileFormat: f.fileFormat}
	}
	if f.useAskpass {
		count++
		spec = HandoffSpec{Kind: HandoffAskpass}
	}
	if fs.Changed("arg-placeholder") {
		count++
		if f.argPlaceholder == "" {
			return spec, errors.New("--arg-placeholder cannot be empty")
		}
		found := false
		for _, a := range target {
			if strings.Contains(a, f.argPlaceholder) {
				found = true
				break
			}
		}
		if !found {
			return spec, fmt.Errorf("placeholder %q not found in target command arguments", f.argPlaceholder)
		}
		spec = HandoffSpec{Kind: HandoffArgPlaceholder, ArgPlaceholder: f.argPlaceholder}
	}

	if count == 0 {
		return spec, errors.New("must specify one handoff mode: --env, --env-all, --stdin, --file, --file-env, --askpass, or --arg-placeholder")
	}
	if count > 1 {
		return spec, errors.New("specify only one handoff mode (--env, --env-all, --stdin, --file, --file-env, --askpass, or --arg-placeholder)")
	}
	return spec, nil
}
