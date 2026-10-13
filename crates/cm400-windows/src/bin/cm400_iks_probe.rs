//! Console entry point for the `IKsControl` reachability probe.
//!
//! Exists so the interactive-side evidence is reproducible from this repository instead of from a
//! third-party binary: `cm400-iks-probe status` reads the motor state variable through the KS
//! proxy, and `extend`/`retract` write exactly the two values the protocol allows. Anything else,
//! including a forbidden selector or value, is refused by `cm400-protocol` before a call is made.
//!
//! Exit codes: 0 reachable (read worked), 1 not reachable, 2 bad arguments. An accepted write is
//! reported together with its read-back and marked UNCONFIRMED when the two disagree - this tool
//! never claims a position it could not observe.
//!
//! `--mf` runs the Media Foundation comparison instead of the DirectShow path, and `--by-name`
//! selects the filter by label the way the verified third-party call does. Both exist to attribute a
//! failure between the object, the request and the device; neither is used by the service.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut media_foundation = false;
    let mut by_name = false;
    let mut each = false;
    let mut verb = "status".to_string();
    for arg in &args {
        match arg.as_str() {
            "--mf" => media_foundation = true,
            "--by-name" => by_name = true,
            "--each" => each = true,
            "--all" => {
                for line in cm400_windows::iks_probe::diagnose_all() {
                    println!("{line}");
                }
                std::process::exit(0);
            }
            other => verb = other.to_string(),
        }
    }
    if each {
        // Diagnostic listing: every matching moniker and what the verified read answered on it.
        for line in cm400_windows::iks_probe::diagnose_each() {
            println!("{line}");
        }
        std::process::exit(0);
    }
    let actuate = match verb.as_str() {
        "status" | "" => None,
        "extend" => Some(1u8),
        "retract" => Some(2u8),
        other => {
            eprintln!(
                "usage: cm400-iks-probe [status|extend|retract] [--mf] [--by-name]  (got: {other})"
            );
            std::process::exit(2);
        }
    };

    let (rep, line) = if media_foundation {
        cm400_windows::iks_probe::run_media_foundation(actuate)
    } else if by_name {
        cm400_windows::iks_probe::run_diagnostic_by_name(actuate)
    } else {
        cm400_windows::iks_probe::run(actuate)
    };
    println!(
        "stages: via={} com={} sources={} matched={} ksp={} get_cur={:?} returned={} shape={:?} read_back={:?} name=\"{}\"",
        rep.via,
        rep.com_ok,
        rep.sources,
        rep.matched,
        rep.ksp_ok,
        rep.get_cur,
        rep.get_returned,
        rep.shape,
        rep.read_back,
        rep.name
    );
    println!(
        "object: identity-source={} bound-via={} identity=\"{}\"",
        rep.identity_source, rep.bound_via, rep.identity
    );
    if !rep.attempts.is_empty() {
        println!("attempts: {}", rep.attempts.join("; "));
    }
    if !rep.failure.is_empty() {
        println!("failure: {}", rep.failure);
    }
    println!("verdict: {}", rep.verdict());
    if let Some(line) = line {
        println!("actuation: {line}");
    }
    // A reachable read is the success condition. An actuation that disagreed with its read-back is
    // printed but does not change the exit code, because the read stage is what this tool claims.
    std::process::exit(if rep.ksp_ok && rep.get_cur.is_some() {
        0
    } else {
        1
    });
}
