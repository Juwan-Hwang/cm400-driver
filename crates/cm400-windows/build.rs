// Records where a binary came from, so a shipped file can be tied back to a commit without trusting
// anybody's notes. This is provenance bookkeeping, not a proof: what it makes checkable is "the bytes
// carrying this string were compiled from commit X, with the working tree clean/dirty, at time T".
// Whether those bytes were then signed by whom they claim is a separate question, answered by the
// Authenticode signature and the catalog verification, not by this file.
use std::process::Command;

fn git(args: &[&str]) -> String {
    let Ok(output) = Command::new("git").args(args).output() else {
        return "unknown".to_string();
    };
    if !output.status.success() {
        return "unknown".to_string();
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rustc-env=CM400_GIT_COMMIT={}",
        git(&["rev-parse", "--verify", "HEAD"])
    );
    println!(
        "cargo:rustc-env=CM400_GIT_TAG={}",
        git(&["describe", "--tags", "--always", "--dirty"])
    );
    // anything tracked but modified counts as dirty: an untracked helper file must not make a release build
    // look modified, which is why this asks about tracked paths only
    let status = git(&["status", "--porcelain", "--untracked-files=no"]);
    let dirty = if status == "unknown" {
        "unknown"
    } else if status.trim().is_empty() {
        "clean"
    } else {
        "dirty"
    };
    println!("cargo:rustc-env=CM400_GIT_DIRTY={dirty}");
    println!(
        "cargo:rustc-env=CM400_BUILD_TIME={}",
        git(&["log", "-1", "--format=%cI"])
    );
}
