import os, shutil
from utils import *

NOTES_DIR_PATH = os.path.expanduser("~/.local/share/notist/notes")


def init():
    if not os.path.exists(NOTES_DIR_PATH):
        os.makedirs(NOTES_DIR_PATH)


def mainMenu():
    print("\n=== NotIST ===")
    print("1. Create a Note")
    print("2. Show Notes List")
    print("3. View Note Content")
    print("4. Edit a Note")
    print("5. Delete a Note")
    print("6. Exit")

    choice = input("Choose an option: ")
    return choice


def createNote():
    title = input("Enter note title: ")
    if not title.strip():
        raise ValueError("Title cannot be empty.")

    noteDir = os.path.join(NOTES_DIR_PATH, title)
    if os.path.exists(noteDir):
        raise ValueError("A note with this title already exists.")

    os.makedirs(noteDir)

    KeyFile = os.path.join(noteDir, "key")
    noteKey = generate_key()
    store_key(noteKey, KeyFile)

    notePath = os.path.join(noteDir, "v1.notist")

    content = input("Enter note content: ")

    writeToFile(
        notePath,
        KeyFile,
        title,
        content,
        1,
    )

    print(f"Note '{title}' created successfully!")


def getNextVersion(noteDir):
    """Returns the next available version number for the note."""
    versions = [f for f in os.listdir(noteDir) if f.endswith(".notist")]
    versionNumbers = []
    for version in versions:
        try:
            versionNumber = int(version.replace(".notist", "").replace("v", ""))
            versionNumbers.append(versionNumber)
        except ValueError:
            continue
    return max(versionNumbers, default=0) + 1


def displayNotesList():
    """Displays the list of notes with their latest version."""
    if not os.path.exists(NOTES_DIR_PATH):
        print("No notes available.")
        return

    noteDirs = [
        d
        for d in os.listdir(NOTES_DIR_PATH)
        if os.path.isdir(os.path.join(NOTES_DIR_PATH, d))
    ]
    if not noteDirs:
        print("No notes available.")
        return

    print("\nAvailable Notes (showing latest version):")
    for idx, note in enumerate(noteDirs, start=1):
        noteDir = os.path.join(NOTES_DIR_PATH, note)
        versions = sorted([f for f in os.listdir(noteDir) if f.endswith(".notist")])

        if versions:
            latestVersion = versions[-1]
            latestVersionDisplay = latestVersion.replace(".notist", "")
            print(f"{idx}. {note} ({latestVersionDisplay})")
        else:
            print(f"{idx}. {note} (No versions available)")


def viewNoteContent():
    if not os.path.exists(NOTES_DIR_PATH):
        print("No notes available.")
        return

    noteDirs = [
        d
        for d in os.listdir(NOTES_DIR_PATH)
        if os.path.isdir(os.path.join(NOTES_DIR_PATH, d))
    ]
    if not noteDirs:
        print("No notes available.")
        return

    displayNotesList()

    choice = input("Select a note by number to view its content: ")
    choice = int(choice)
    selectedNote = noteDirs[choice - 1]
    noteDir = os.path.join(NOTES_DIR_PATH, selectedNote)

    KeyFile = os.path.join(noteDir, "key")

    version = selectVersion(noteDir)
    if version is None:
        return

    filepath = os.path.join(noteDir, version)

    content = readFromFile(filepath, KeyFile)

    print("\nContent of the selected note version:")
    print(content)


def selectVersion(noteDir: str) -> Optional[str]:
    """Helper function to allow selecting a version for a note."""
    versions = sorted([f for f in os.listdir(noteDir) if f.endswith(".notist")])
    if not versions:
        print("No versions available for this note.")
        return None

    if len(versions) == 1:
        return versions[0]

    print("\nAvailable Versions:")
    for idx, version in enumerate(versions, start=1):
        versionDisplay = version.replace(".notist", "")
        print(f"{idx}. {versionDisplay}")

    choice = input("Select a version to view: ").strip()
    choice = int(choice)
    if 1 <= choice <= len(versions):
        return versions[choice - 1]
    else:
        print("Invalid selection.")
        return None


def editNote():
    if not os.path.exists(NOTES_DIR_PATH):
        print("No notes available.")
        return

    noteDirs = [
        d
        for d in os.listdir(NOTES_DIR_PATH)
        if os.path.isdir(os.path.join(NOTES_DIR_PATH, d))
    ]
    if not noteDirs:
        print("No notes available.")
        return

    displayNotesList()

    choice = input("Select a note by number to edit: ")
    choice = int(choice)
    selectedNote = noteDirs[choice - 1]
    noteDir = os.path.join(NOTES_DIR_PATH, selectedNote)
    version = selectVersion(noteDir)
    if version is None:
        return

    filepath = os.path.join(noteDir, version)
    KeyFile = os.path.join(noteDir, "key")
    content = readFromFile(filepath, KeyFile)
    print("\nCurrent Content:")
    print(content)

    newContent = input("\nEnter new content (THIS WILL OVERWRITE OLD CONTENT): ")
    newVersion = getNextVersion(noteDir)
    newFilepath = os.path.join(noteDir, f"v{newVersion}.notist")
    keyFile = os.path.join(noteDir, "key")

    writeToFile(
        newFilepath,
        keyFile,
        selectedNote,
        newContent,
        newVersion,
    )
    print(f"Note '{selectedNote}' version {newVersion} updated successfully!")


def deleteNote():
    if not os.path.exists(NOTES_DIR_PATH):
        print("No notes available.")
        return

    noteDirs = [
        d
        for d in os.listdir(NOTES_DIR_PATH)
        if os.path.isdir(os.path.join(NOTES_DIR_PATH, d))
    ]
    if not noteDirs:
        print("No notes available.")
        return

    displayNotesList()

    choice = input("Select a note by number to delete: ")
    choice = int(choice)
    selectedNote = noteDirs[choice - 1]
    noteDir = os.path.join(NOTES_DIR_PATH, selectedNote)

    versions = [f for f in os.listdir(noteDir) if f.endswith(".notist")]

    if len(versions) <= 1:
        shutil.rmtree(noteDir)
        print(f"All versions of note '{selectedNote}' deleted successfully!")
        return

    deleteAll = input("Delete all versions of the note? (yes/no): ").strip().lower()
    if deleteAll == "yes":
        shutil.rmtree(noteDir)
        print(f"All versions of note '{selectedNote}' deleted successfully!")

    else:
        version = selectVersion(noteDir)
        if version is None:
            return

        filepath = os.path.join(noteDir, version)
        os.remove(filepath)
        print(f"Note '{selectedNote}' version '{version}' deleted successfully!")

        if not os.listdir(noteDir):
            os.rmdir(noteDir)


def main():
    init()

    while True:
        choice = mainMenu()
        if choice == "1":
            createNote()
        elif choice == "2":
            displayNotesList()
        elif choice == "3":
            viewNoteContent()
        elif choice == "4":
            editNote()
        elif choice == "5":
            deleteNote()
        elif choice == "6":
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
