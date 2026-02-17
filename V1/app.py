from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash  # Note: Utilisez bcrypt pour plus de sécurité

app = Flask(__name__)
app.config['SECRET_KEY'] = 'votre_cle_secrete'  # Changez cela !
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///portal.db'  # Ou 'postgresql://user:pass@localhost/db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modèle Utilisateur
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    verified = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), default='user')

# Modèle Mapping (exemple simple)
class Mapping(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    resource = db.Column(db.String(150))  # Ex. 'projet1', 'groupeA'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route de connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password) and user.verified:
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Connexion échouée. Vérifiez vos identifiants ou statut vérifié.')
    return render_template('login.html')  # Créez un template HTML pour cela

# Route d'inscription (avec vérification pending)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')  # Ou bcrypt
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Inscription réussie. En attente de vérification par admin.')
        # Envoyez email de confirmation ici (utilisez flask-mail)
    return render_template('register.html')

# Dashboard (exemple)
@app.route('/dashboard')
@login_required
def dashboard():
    return f'Bonjour, {current_user.username}! Vous êtes connecté.'

# Admin : Vérification utilisateurs
@app.route('/admin/verify/<int:user_id>')
@login_required
def verify_user(user_id):
    if current_user.role != 'admin':
        return 'Accès refusé.'
    user = User.query.get(user_id)
    user.verified = True
    db.session.commit()
    return 'Utilisateur vérifié.'

# Admin : Mapping
@app.route('/admin/map', methods=['POST'])
@login_required
def map_user():
    if current_user.role != 'admin':
        return 'Accès refusé.'
    user_id = request.form['user_id']
    resource = request.form['resource']
    new_mapping = Mapping(user_id=user_id, resource=resource)
    db.session.add(new_mapping)
    db.session.commit()
    return 'Mapping ajouté.'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Crée les tables si pas existantes
    app.run(debug=True, port=5001)
