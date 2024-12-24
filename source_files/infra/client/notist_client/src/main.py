from notist_client.client import NoteISTClient

def main():
    # Configuration
    host = "192.168.1.228"
    port = 5000
    cert_path = "/home/vagrant/certs/ca.crt"

    # Create client instance
    client = NoteISTClient(host=host, port=port, cert_path=cert_path)

    while True:
        try:
            choice = display_menu()
            handle_choice(client, choice)
            if choice == "7":
                break
        except Exception as e:
            print(f"Error: {e}")

def display_menu() -> str:
    """Display the main menu and get user choice."""
    print("\n=== NoteIST ===")
    print("1. Create a Note")
    print("2. Show Notes List")
    print("3. View Note Content")
    print("4. Edit a Note")
    print("5. Delete a Note")
    print("6. Push changes to remote server")
    print("7: Pull changes from remote server")
    print("8. Exit")
    return input("Choose an option: ")

def handle_choice(client: NoteISTClient, choice: str) -> None:
    """Handle the user's menu choice."""
    if choice == "1":
        title = input("Enter note title: ")
        content = input("Enter note content: ")
        client.create_note(title, content)
        
    elif choice == "2":
        notes = client.get_note_list()
        if not notes:
            print("No notes available.")
            return
            
        print("\nAvailable Notes:")
        for i, note in enumerate(notes, 1):
            print(f"{i}. {note['title']} (v{note['version']})")
            
    elif choice == "3":
        title = input("Enter note title: ")
        version = input("Enter version number (press Enter for latest): ").strip()
        version = int(version) if version else None
        note = client.get_note_content(title, version)
        print(f"\nTitle: {note['title']}")
        print(f"Content: {note['content']}")
        
    elif choice == "4":
        title = input("Enter note title: ")
        new_content = input("Enter new content: ")
        client.edit_note(title, new_content)
        
    elif choice == "5":
        title = input("Enter note title: ")
        client.delete_note(title)
        
    elif choice == "6":
        response = client.push_changes()
        print(f"Server response: {response.status} - {response.message}")

    elif choice == "7":
        response = client.pull_changes()
        print(f"Server response: {response.status} - {response.message}")

if __name__ == "__main__":
    main()
