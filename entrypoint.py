from main import app
from teacher_directory import install_teacher_directory

# Safe additive composition: existing room server app + Teacher Directory V1.
install_teacher_directory(app)
