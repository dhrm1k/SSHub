//! OpenSSH algorithm compatibility options.
//!
//! Modern OpenSSH clients drop SHA-1 host keys / pubkeys (`ssh-rsa`) and some
//! older KEX methods by default. Routers, appliances, and older Dropbear/OpenSSH
//! servers still offer only those. Appending them with a leading `+` keeps the
//! client's preferred modern set first and only falls back when the peer has
//! nothing else — no pre-connect probe, so connect latency is unchanged.

/// `-o Key=Value` pairs spliced after `ssh` on every connect path.
///
/// Values use OpenSSH's `+` form: append to the built-in defaults rather than
/// replacing them, so modern peers keep negotiating modern algorithms.
pub const SSH_COMPAT_OPTS: &[&str] = &[
    "-o",
    "HostKeyAlgorithms=+ssh-rsa",
    "-o",
    "PubkeyAcceptedAlgorithms=+ssh-rsa",
    "-o",
    "KexAlgorithms=+diffie-hellman-group14-sha1",
];

/// Insert [`SSH_COMPAT_OPTS`] after `argv[0]` when the program is `ssh`.
/// Idempotent: skips when `HostKeyAlgorithms=` is already present.
pub fn splice_ssh_compat_options(argv: &mut Vec<String>) {
    if argv.first().map(String::as_str) != Some("ssh") {
        return;
    }
    if argv
        .iter()
        .any(|a| a.starts_with("HostKeyAlgorithms=") || a.contains("HostKeyAlgorithms="))
    {
        return;
    }
    argv.splice(1..1, SSH_COMPAT_OPTS.iter().map(|s| (*s).to_string()));
}

/// Append the compat `-o` flags to an existing `ssh …` command string (mosh's
/// `--ssh=` value), or return a fresh `ssh -o …` command when none exists yet.
pub fn mosh_ssh_command_with_compat(existing: Option<&str>) -> String {
    let base = existing.unwrap_or("ssh").trim();
    let base = if base.is_empty() { "ssh" } else { base };
    if base.contains("HostKeyAlgorithms=") {
        return base.to_string();
    }
    let mut cmd = base.to_string();
    for chunk in SSH_COMPAT_OPTS.chunks(2) {
        // chunks are ("-o", "Key=Value")
        if let [flag, value] = chunk {
            cmd.push(' ');
            cmd.push_str(flag);
            cmd.push(' ');
            cmd.push_str(value);
        }
    }
    cmd
}

/// Ensure a `mosh` argv's inner ssh carries the compat options.
pub fn inject_mosh_ssh_compat(mut argv: Vec<String>) -> Vec<String> {
    if argv.first().map(String::as_str) != Some("mosh") {
        return argv;
    }
    if let Some(idx) = argv.iter().position(|a| a.starts_with("--ssh=")) {
        let ssh_cmd = &argv[idx]["--ssh=".len()..];
        argv[idx] = format!("--ssh={}", mosh_ssh_command_with_compat(Some(ssh_cmd)));
        return argv;
    }
    if argv.len() >= 2 {
        argv.insert(
            1,
            format!("--ssh={}", mosh_ssh_command_with_compat(None)),
        );
    }
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splice_inserts_after_ssh() {
        let mut argv = vec!["ssh".into(), "root@h".into()];
        splice_ssh_compat_options(&mut argv);
        assert_eq!(argv[0], "ssh");
        assert!(argv.iter().any(|a| a == "HostKeyAlgorithms=+ssh-rsa"));
        assert!(argv.iter().any(|a| a == "PubkeyAcceptedAlgorithms=+ssh-rsa"));
        assert!(argv
            .iter()
            .any(|a| a == "KexAlgorithms=+diffie-hellman-group14-sha1"));
        assert_eq!(argv.last().map(String::as_str), Some("root@h"));
    }

    #[test]
    fn splice_is_idempotent() {
        let mut argv = vec!["ssh".into(), "h".into()];
        splice_ssh_compat_options(&mut argv);
        let once = argv.clone();
        splice_ssh_compat_options(&mut argv);
        assert_eq!(argv, once);
    }

    #[test]
    fn splice_skips_non_ssh() {
        let mut argv = vec!["mosh".into(), "h".into()];
        splice_ssh_compat_options(&mut argv);
        assert_eq!(argv, vec!["mosh".to_string(), "h".to_string()]);
    }

    #[test]
    fn mosh_inject_adds_ssh_wrapper() {
        let argv = inject_mosh_ssh_compat(vec!["mosh".into(), "roam".into()]);
        assert_eq!(argv[0], "mosh");
        assert!(argv[1].starts_with("--ssh=ssh "));
        assert!(argv[1].contains("HostKeyAlgorithms=+ssh-rsa"));
        assert_eq!(argv[2], "roam");
    }

    #[test]
    fn mosh_inject_extends_existing_ssh() {
        let argv = inject_mosh_ssh_compat(vec![
            "mosh".into(),
            "--ssh=ssh -p 2222".into(),
            "h".into(),
        ]);
        assert!(argv[1].starts_with("--ssh=ssh -p 2222 "));
        assert!(argv[1].contains("HostKeyAlgorithms=+ssh-rsa"));
    }
}
