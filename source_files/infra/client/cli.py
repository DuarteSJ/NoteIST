import os
from utils import readFromFile, writeToFile

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
    try:
        title = input("Enter note title: ")
        if not title.strip():
            raise ValueError("Title cannot be empty.")
        
        noteDir = os.path.join(NOTES_DIR_PATH, title)
        if os.path.exists(noteDir):
            raise ValueError("A note with this title already exists.")

        os.makedirs(noteDir)
        notePath = os.path.join(noteDir, "v1.notist")
        
        content = input("Enter note content: ")
        
        writeToFile(notePath, os.path.expanduser("~/.config/secure_document/key"), title, content, 1)

        print(f"Note '{title}' created successfully!")
    except Exception as e:
        print(f"Error creating note: {e}")

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

    return max(versionNumbers, default=0) + 1  # Default to 1 if no versions exist

def displayNotesList():
    """Displays the list of notes with their latest version."""
    try:
        if not os.path.exists(NOTES_DIR_PATH):
            print("No notes available.")
            return

        noteDirs = [d for d in os.listdir(NOTES_DIR_PATH) if os.path.isdir(os.path.join(NOTES_DIR_PATH, d))]
        if not noteDirs:
            print("No notes available.")
            return

        print("\nAvailable Notes (showing latest version):")
        for idx, note in enumerate(noteDirs, start=1):
            noteDir = os.path.join(NOTES_DIR_PATH, note)
            versions = sorted(os.listdir(noteDir))  # Get versions and sort them
            
            if versions:
                latestVersion = versions[-1]  # The last (most recent) version
                latestVersionDisplay = latestVersion.replace(".notist", "")
                print(f"{idx}. {note} ({latestVersionDisplay})")
            else:
                print(f"{idx}. {note} (No versions available)")

    except Exception as e:
        print(f"Error showing notes list: {e}")

def viewNoteContent():
    try:
        if not os.path.exists(NOTES_DIR_PATH):
            print("No notes available.")
            return

        noteDirs = [d for d in os.listdir(NOTES_DIR_PATH) if os.path.isdir(os.path.join(NOTES_DIR_PATH, d))]
        if not noteDirs:
            print("No notes available.")
            return

        displayNotesList()  # Display the notes list
        
        # Ask the user to select a note by number
        choice = input("Select a note by number to view its content: ")
        try:
            choice = int(choice)
            selectedNote = noteDirs[choice - 1]
            noteDir = os.path.join(NOTES_DIR_PATH, selectedNote)

            versions = sorted(os.listdir(noteDir))
            if not versions:
                print("No versions available for this note.")
                return

            version = selectVersion(versions, selectedNote)
            if version is None:
                return

            filepath = os.path.join(noteDir, version)
            content = readFromFile(filepath, os.path.expanduser("~/.config/secure_document/key"))

            print("\nContent of the selected note version:")
            print(content)
        except (ValueError, IndexError):
            print("Invalid selection.")
            return
    except Exception as e:
        print(f"Error viewing note content: {e}")

def selectVersion(versions, selectedNote):
    """Helper function to allow selecting a version for a note."""
    if len(versions) == 1:
        return versions[0]
    
    print("\nAvailable Versions:")
    for idx, version in enumerate(versions, start=1):
        versionDisplay = version.replace(".notist", "")
        print(f"{idx}. {selectedNote}.{versionDisplay}")

    choice = input("Select a version to view: ")
    try:
        version = versions[int(choice) - 1]
        return version
    except (ValueError, IndexError):
        print("Invalid selection.")
        return None

def editNote():
    try:
        if not os.path.exists(NOTES_DIR_PATH):
            print("No notes available.")
            return

        noteDirs = [d for d in os.listdir(NOTES_DIR_PATH) if os.path.isdir(os.path.join(NOTES_DIR_PATH, d))]
        if not noteDirs:
            print("No notes available.")
            return

        displayNotesList()  # Display the notes list
        
        # Ask the user to select a note by number
        choice = input("Select a note by number to edit: ")
        try:
            choice = int(choice)
            selectedNote = noteDirs[choice - 1]
            noteDir = os.path.join(NOTES_DIR_PATH, selectedNote)

            versions = sorted(os.listdir(noteDir))
            if not versions:
                print("No versions available for this note.")
                return

            version = selectVersion(versions, selectedNote)
            if version is None:
                return

            filepath = os.path.join(noteDir, version)
            content = readFromFile(filepath, os.path.expanduser("~/.config/secure_document/key"))
            print("\nCurrent Content:")
            print(content)

            newContent = input("\nEnter new content (THIS WILL OVERWRITE OLD CONTENT): ")
            newVersion = getNextVersion(noteDir)
            newFilepath = os.path.join(noteDir, f"v{newVersion}.notist")

            writeToFile(newFilepath, os.path.expanduser("~/.config/secure_document/key"), selectedNote, newContent, newVersion)
            print(f"Note '{selectedNote}' version {newVersion} updated successfully!")
        except (ValueError, IndexError):
            print("Invalid selection.")
            return
    except Exception as e:
        print(f"Error editing note: {e}")

def deleteNote():
    try:
        if not os.path.exists(NOTES_DIR_PATH):
            print("No notes available.")
            return

        noteDirs = [d for d in os.listdir(NOTES_DIR_PATH) if os.path.isdir(os.path.join(NOTES_DIR_PATH, d))]
        if not noteDirs:
            print("No notes available.")
            return

        displayNotesList()  # Display the notes list
        
        # Ask the user to select a note by number
        choice = input("Select a note by number to delete: ")
        try:
            choice = int(choice)
            selectedNote = noteDirs[choice - 1]
            noteDir = os.path.join(NOTES_DIR_PATH, selectedNote)

            versions = sorted(os.listdir(noteDir))
            if not versions:
                print("No versions available for this note.")
                return

            version = selectVersion(versions, selectedNote)
            if version is None:
                return

            filepath = os.path.join(noteDir, version)
            os.remove(filepath)
            print(f"Note '{selectedNote}' version '{version}' deleted successfully!")

            if not os.listdir(noteDir):
                os.rmdir(noteDir)
        except (ValueError, IndexError):
            print("Invalid selection.")
            return
    except Exception as e:
        print(f"Error deleting note: {e}")

def main():
    try:
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
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
