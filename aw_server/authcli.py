"""Admin CLI for CEPEM Watch multi-user tokens.

Usage:
    python -m aw_server.authcli add <username> [--admin] [--testing]
    python -m aw_server.authcli reissue <username> [--testing]
    python -m aw_server.authcli revoke <username> [--testing]
    python -m aw_server.authcli list [--testing]

Tokens are printed once, at creation/reissue. Store them securely; only their
SHA-256 hash is kept on the server.
"""
import argparse
import sys

from . import auth


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="aw-server users", description="Manage CEPEM Watch users and API tokens"
    )
    parser.add_argument(
        "--testing", action="store_true", help="Operate on the testing user store"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="Create a user and print a new token")
    p_add.add_argument("username")
    p_add.add_argument("--admin", action="store_true", help="Grant the admin role")

    p_re = sub.add_parser("reissue", help="Rotate a user's token")
    p_re.add_argument("username")

    p_rv = sub.add_parser("revoke", help="Delete a user")
    p_rv.add_argument("username")

    sub.add_parser("list", help="List users")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "add":
            token = auth.add_user(
                args.username,
                role="admin" if args.admin else "user",
                testing=args.testing,
            )
            print(f"User '{args.username}' created (role={'admin' if args.admin else 'user'}).")
            print("API token (shown once - store it now):")
            print(f"  {token}")
        elif args.cmd == "reissue":
            token = auth.reissue_token(args.username, testing=args.testing)
            print(f"New API token for '{args.username}' (shown once):")
            print(f"  {token}")
        elif args.cmd == "revoke":
            auth.revoke_user(args.username, testing=args.testing)
            print(f"User '{args.username}' revoked.")
        elif args.cmd == "list":
            users = auth.list_users(testing=args.testing)
            if not users:
                print("No users.")
            for u in users:
                print(f"  {u['username']:<24} role={u['role']:<6} created={u['created']}")
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
