import subprocess


def clean_subprocess_output(output) -> str:
    # Remove trailing newlines and decode bytes to string if necessary
    cleaned_output = output.stdout
    stripped_output = (
        cleaned_output.rstrip(b"\n")
        if isinstance(cleaned_output, bytes)
        else cleaned_output.rstrip("\n")
    )
    string_output = (
        stripped_output.decode("utf-8")
        if isinstance(stripped_output, bytes)
        else stripped_output
    )
    return string_output


def git_track(file_path, message="Update via wg-access-manager") -> None:
    # Stage the file
    subprocess.run(["git", "add", file_path], check=True)
    # Commit the changes
    subprocess.run(["git", "commit", "-m", message], check=True)
