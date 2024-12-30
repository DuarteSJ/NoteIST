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
    print("6. Add contributor to a note")
    print("7. Remove contributor from a note")
    print("8. Push changes to remote server")
    print("9: Pull changes from remote server")
    print("10. Exit")
    return input("Choose an option: ")


def handle_choice(client: NoteISTClient, choice: str) -> None:
    """Handle the user's menu choice."""
    if choice == "1":
        title = input("Enter note title: ")
        content = input("Enter note content: ")
        client.create_note(title, content)

    elif choice == "2":
        client.list_notes()

    elif choice == "3":
        client.view_note()

    elif choice == "4":
        client.edit_note()

    elif choice == "5":
        client.delete_note()

    elif choice == "6":
        client.add_contributor()

    elif choice == "7":
        client.remove_contributor()

    elif choice == "8":
        client.push_changes()

    elif choice == "9":
        client.pull_changes()

    elif choice == "10":
        exit(0)


if __name__ == "__main__":
    main()
