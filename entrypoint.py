from main import app
from teacher_directory import install_teacher_directory
from family_accounts import install_family_accounts

# Safe additive composition: existing room server + Teacher Directory + Family Accounts.
install_teacher_directory(app)
install_family_accounts(app)
