from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import psycopg2
import psycopg2.extras
import bcrypt
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

# Database configuration
DATABASE_CONFIG = {
    'host': 'localhost',
    'database': 'workofart_db',
    'user': 'postgres',
    'password': 'postgres'
}

# Upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db_connection():
    """Get database connection"""
    try:
        conn = psycopg2.connect(**DATABASE_CONFIG)
        return conn
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")
        return None

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    """Initialize database tables"""
    conn = get_db_connection()
    if not conn:
        print("Could not connect to database")
        return

    cur = conn.cursor()

    try:
        # Create users table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'visitor',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create artists table (with user_id link)
        # Added UNIQUE constraint to name for consistency, this would require DB reset or ALTER TABLE
        cur.execute('''
            CREATE TABLE IF NOT EXISTS artists (
                id SERIAL PRIMARY KEY,
                user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(255) UNIQUE NOT NULL, -- Added UNIQUE
                biography TEXT,
                birth_year INTEGER,
                death_year INTEGER,
                nationality VARCHAR(100),
                image_url VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create artworks table (with price column)
        cur.execute('''
            CREATE TABLE IF NOT EXISTS artworks (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                artist_id INTEGER REFERENCES artists(id),
                description TEXT,
                medium VARCHAR(100),
                year_created INTEGER,
                dimensions VARCHAR(100),
                image_url VARCHAR(500),
                price DECIMAL(10,2),
                is_featured BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create events table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                event_date DATE,
                end_date DATE,
                location VARCHAR(255),
                ticket_price DECIMAL(10,2),
                image_url VARCHAR(500),
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create purchases table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS purchases (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                artwork_id INTEGER REFERENCES artworks(id) ON DELETE RESTRICT,
                purchase_price DECIMAL(10,2) NOT NULL,
                purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')


        conn.commit()
        print("Database tables created successfully")

        # Create default admin user if doesn't exist
        cur.execute("SELECT * FROM users WHERE username = 'admin'")
        if not cur.fetchone():
            admin_password = generate_password_hash('admin123')
            cur.execute('''
                INSERT INTO users (username, email, password_hash, role)
                VALUES ('admin', 'admin@workofart.com', %s, 'admin')
            ''', (admin_password,))
            conn.commit()
            print("Default admin user created (admin/admin123)")

    except psycopg2.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

# --- Authentication Decorators ---
def login_required(f):
    """Decorator for routes that require login"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    """Decorator for routes that require admin access"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def artist_role_required(f):
    """Decorator for routes that require an artist role."""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if session.get('role') != 'artist' and session.get('role') != 'admin': # Admin can also access artist routes
            flash('Artist access required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def artist_profile_required(f):
    """Decorator for routes that require a logged-in artist with a completed profile."""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if session.get('role') != 'artist' and session.get('role') != 'admin': # Admin can also access artist routes
            flash('Artist access required.', 'error')
            return redirect(url_for('index'))

        # Check if the artist has a profile
        if 'artist_id' not in session:
            flash('Please complete your artist profile first.', 'info')
            return redirect(url_for('create_artist_profile'))

        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# --- User Authentication and Session Management ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        register_as_artist = 'register_as_artist' in request.form

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html', username=username, email=email, register_as_artist=register_as_artist)

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html', username=username, email=email, register_as_artist=register_as_artist)

        hashed_password = generate_password_hash(password)
        role = 'artist' if register_as_artist else 'visitor'

        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return render_template('register.html', username=username, email=email, register_as_artist=register_as_artist)

        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s) RETURNING id",
                (username, email, hashed_password, role)
            )
            user_id = cur.fetchone()[0]
            conn.commit()

            session['user_id'] = user_id
            session['username'] = username
            session['role'] = role

            flash(f'Account created successfully for {username}!', 'success')
            if role == 'artist':
                return redirect(url_for('create_artist_profile'))
            else:
                return redirect(url_for('index'))

        except psycopg2.IntegrityError as e:
            conn.rollback()
            if "users_username_key" in str(e):
                flash('Username already exists.', 'error')
            elif "users_email_key" in str(e):
                flash('Email already exists.', 'error')
            else:
                flash(f'Database error: {e}', 'error')
            return render_template('register.html', username=username, email=email, register_as_artist=register_as_artist)
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'error')
            return render_template('register.html', username=username, email=email, register_as_artist=register_as_artist)
        finally:
            cur.close()
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'error')
            return render_template('login.html')

        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        try:
            cur.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cur.fetchone()

            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']

                if user['role'] == 'artist':
                    cur.execute('SELECT id FROM artists WHERE user_id = %s', (user['id'],))
                    artist_profile = cur.fetchone()
                    if artist_profile:
                        session['artist_id'] = artist_profile['id']

                flash(f'Welcome back, {username}!', 'success')

                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password', 'error')
        except Exception as e:
            flash(f'An unexpected error occurred during login: {e}', 'error')
        finally:
            cur.close()
            conn.close()

    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear() # Clears user_id, username, role, and artist_id
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/my_account')
@login_required
def my_account():
    """Displays user's account details and purchase history."""
    user_id = session['user_id']

    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'error')
        return redirect(url_for('index'))

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    try:
        cur.execute("SELECT username, email, role FROM users WHERE id = %s", (user_id,))
        user_info = cur.fetchone()

        artist_profile = None
        if user_info and user_info['role'] == 'artist':
            cur.execute("SELECT id, name FROM artists WHERE user_id = %s", (user_id,))
            artist_profile = cur.fetchone()

        cur.execute("""
            SELECT p.purchase_price, p.purchase_date,
                   a.title AS artwork_title, a.image_url AS artwork_image_url,
                   ar.name AS artist_name, a.id AS artwork_id
            FROM purchases p
            JOIN artworks a ON p.artwork_id = a.id
            LEFT JOIN artists ar ON a.artist_id = ar.id
            WHERE p.user_id = %s
            ORDER BY p.purchase_date DESC
        """, (user_id,))
        purchases = cur.fetchall()

        total_spent = sum(p['purchase_price'] for p in purchases) if purchases else 0.0

        return render_template('my_account.html',
                               user_info=user_info,
                               artist_profile=artist_profile, # Pass artist profile
                               purchases=purchases,
                               total_spent=total_spent)
    except Exception as e:
        flash(f'Error retrieving account information: {e}', 'error')
        return redirect(url_for('index'))
    finally:
        cur.close()
        conn.close()

@app.route('/my_account/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Allows a user to edit their account and optionally artist profile."""
    user_id = session['user_id']
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'error')
        return redirect(url_for('my_account'))

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    user_info = {}
    artist_profile = {}
    current_artist_image = None # To display current image in template

    try:
        cur.execute("SELECT id, username, email, role FROM users WHERE id = %s", (user_id,))
        user_info = cur.fetchone()

        if user_info['role'] == 'artist':
            cur.execute("SELECT id, name, biography, birth_year, death_year, nationality, image_url FROM artists WHERE user_id = %s", (user_id,))
            artist_profile = cur.fetchone()
            if artist_profile:
                current_artist_image = artist_profile['image_url']
            else:
                # Artist role but no profile yet, redirect to create it
                flash("Please create your artist profile first.", "info")
                return redirect(url_for('create_artist_profile'))

    except Exception as e:
        flash(f'Error loading profile data: {e}', 'error')
        cur.close()
        conn.close()
        return redirect(url_for('my_account'))

    if request.method == 'POST':
        # --- User Profile Update ---
        new_username = request.form['username']
        new_email = request.form['email']
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        user_updates = []
        user_params = []

        if new_username != user_info['username']:
            user_updates.append("username = %s")
            user_params.append(new_username)
        if new_email != user_info['email']:
            user_updates.append("email = %s")
            user_params.append(new_email)

        if new_password:
            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
                return render_template('edit_profile.html', user_info=user_info, artist_profile=artist_profile, current_artist_image=current_artist_image)
            if len(new_password) < 6:
                flash('New password must be at least 6 characters long.', 'error')
                return render_template('edit_profile.html', user_info=user_info, artist_profile=artist_profile, current_artist_image=current_artist_image)
            user_updates.append("password_hash = %s")
            user_params.append(generate_password_hash(new_password))

        # --- Artist Profile Update (if applicable) ---
        artist_updates = []
        artist_params = []
        new_artist_image_url = current_artist_image # Default to current image

        if user_info['role'] == 'artist' and artist_profile:
            new_artist_name = request.form['artist_name']
            new_biography = request.form.get('biography')
            new_birth_year = request.form.get('birth_year')
            new_death_year = request.form.get('death_year')
            new_nationality = request.form.get('nationality')

            if new_artist_name != artist_profile['name']:
                artist_updates.append("name = %s")
                artist_params.append(new_artist_name)
            if new_biography != artist_profile['biography']:
                artist_updates.append("biography = %s")
                artist_params.append(new_biography)
            if (new_birth_year and int(new_birth_year) != (artist_profile['birth_year'] or 0)) or (not new_birth_year and artist_profile['birth_year'] is not None):
                artist_updates.append("birth_year = %s")
                artist_params.append(int(new_birth_year) if new_birth_year else None)
            if (new_death_year and int(new_death_year) != (artist_profile['death_year'] or 0)) or (not new_death_year and artist_profile['death_year'] is not None):
                artist_updates.append("death_year = %s")
                artist_params.append(int(new_death_year) if new_death_year else None)
            if new_nationality != artist_profile['nationality']:
                artist_updates.append("nationality = %s")
                artist_params.append(new_nationality)

            # Handle artist image upload
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    # Delete old image if it's not the default placeholder
                    if current_artist_image and not current_artist_image.startswith('/static/default_images/'): # Adjust if you have default images
                        try:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(current_artist_image)))
                        except Exception as e:
                            print(f"Error deleting old artist image: {e}")

                    filename = secure_filename(file.filename)
                    unique_filename = str(uuid.uuid4()) + '_' + filename
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    file.save(file_path)
                    new_artist_image_url = f'/static/uploads/{unique_filename}'
                    artist_updates.append("image_url = %s")
                    artist_params.append(new_artist_image_url)
                elif file.filename != '':
                    flash('Invalid image file type. Allowed: png, jpg, jpeg, gif, webp.', 'error')
                    return render_template('edit_profile.html', user_info=user_info, artist_profile=artist_profile, current_artist_image=current_artist_image)


        try:
            # Execute user updates
            if user_updates:
                user_params.append(user_id)
                cur.execute(f"UPDATE users SET {', '.join(user_updates)} WHERE id = %s", tuple(user_params))
                # Update session if username changed
                if new_username != user_info['username']:
                    session['username'] = new_username
                flash('Account information updated.', 'success')

            # Execute artist updates
            if artist_updates:
                artist_params.append(artist_profile['id'])
                cur.execute(f"UPDATE artists SET {', '.join(artist_updates)} WHERE id = %s", tuple(artist_params))
                flash('Artist profile updated.', 'success')
            
            if not user_updates and not artist_updates:
                flash('No changes detected.', 'info')

            conn.commit()
            return redirect(url_for('my_account'))

        except psycopg2.IntegrityError as e:
            conn.rollback()
            if "users_username_key" in str(e):
                flash('Username already exists.', 'error')
            elif "users_email_key" in str(e):
                flash('Email already exists.', 'error')
            elif "artists_name_key" in str(e): # For unique artist name
                flash('Artist name already exists.', 'error')
            else:
                flash(f'Database error: {e}', 'error')
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'error')
        finally:
            cur.close()
            conn.close()
            # If an error occurred and we rendered the template again,
            # we need to ensure the artist_profile data is still consistent for the form.
            # Re-fetch or pass back the POST data for clarity.
            # For simplicity, on error, we just re-render with original fetched data here.
            # A more robust solution would pass back all request.form data.
            return render_template('edit_profile.html', user_info=user_info, artist_profile=artist_profile, current_artist_image=current_artist_image)

    # For GET request
    cur.close()
    conn.close()
    return render_template('edit_profile.html', user_info=user_info, artist_profile=artist_profile, current_artist_image=current_artist_image)


# --- Artist Artwork Submission & Purchase ---
@app.route('/artist/submit_artwork', methods=['GET', 'POST'])
@artist_profile_required
def submit_artwork():
    """Artist route to submit a new artwork."""
    artist_id = session['artist_id']

    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'error')
        return redirect(url_for('index'))

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute('SELECT name FROM artists WHERE id = %s', (artist_id,))
    artist_name_data = cur.fetchone()
    artist_name = artist_name_data['name'] if artist_name_data else "Unknown Artist"

    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description')
        medium = request.form.get('medium')
        year_created = request.form.get('year_created')
        dimensions = request.form.get('dimensions')
        price = request.form.get('price')
        is_featured = 'is_featured' in request.form

        form_data = {
            'artist_name': artist_name, 'title': title, 'description': description,
            'medium': medium, 'year_created': year_created, 'dimensions': dimensions,
            'price': price, 'is_featured': is_featured
        }

        if not price or not price.replace('.', '', 1).isdigit():
            flash('Price is required and must be a valid number.', 'error')
            return render_template('submit_artwork.html', **form_data)

        if float(price) < 0:
            flash('Price cannot be negative.', 'error')
            return render_template('submit_artwork.html', **form_data)

        artwork_image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = str(uuid.uuid4()) + '_' + filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                artwork_image_url = f'/static/uploads/{unique_filename}'
            elif file.filename != '':
                flash('Invalid image file type. Allowed: png, jpg, jpeg, gif, webp.', 'error')
                return render_template('submit_artwork.html', **form_data)
            else:
                flash('Artwork image is required.', 'error')
                return render_template('submit_artwork.html', **form_data)
        else:
            flash('Artwork image is required.', 'error')
            return render_template('submit_artwork.html', **form_data)

        try:
            cur.execute('''
                INSERT INTO artworks (title, artist_id, description, medium, year_created, dimensions, image_url, price, is_featured)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                title,
                artist_id,
                description,
                medium,
                int(year_created) if year_created else None,
                dimensions,
                artwork_image_url,
                float(price),
                is_featured
            ))
            conn.commit()
            flash(f'Artwork "{title}" submitted successfully!', 'success')
            return redirect(url_for('artist_detail', artist_id=artist_id))
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'error')
            return render_template('submit_artwork.html', **form_data)
        finally:
            cur.close()
            conn.close()

    # For GET request
    cur.close()
    conn.close()
    return render_template('submit_artwork.html', artist_name=artist_name)


@app.route('/artwork/<int:artwork_id>/buy', methods=['POST'])
@login_required
def buy_artwork(artwork_id):
    """Handles the purchase of an artwork."""
    user_id = session['user_id']

    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'error')
        return redirect(url_for('artwork_detail', artwork_id=artwork_id))

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("SELECT title, price, artist_id FROM artworks WHERE id = %s", (artwork_id,))
        artwork = cur.fetchone()

        if not artwork:
            flash("Artwork not found.", "error")
            return redirect(url_for('gallery'))
        if artwork['price'] is None or artwork['price'] <= 0:
            flash("This artwork is not available for purchase.", "error")
            return redirect(url_for('artwork_detail', artwork_id=artwork_id))

        if session.get('role') == 'artist' and session.get('artist_id') == artwork['artist_id']:
            flash("You cannot purchase your own artwork.", "error")
            return redirect(url_for('artwork_detail', artwork_id=artwork_id))

        cur.execute("""
            INSERT INTO purchases (user_id, artwork_id, purchase_price)
            VALUES (%s, %s, %s)
        """, (user_id, artwork_id, artwork['price']))
        conn.commit()

        flash(f"'{artwork['title']}' purchased successfully for ${artwork['price']:.2f}!", "success")
        return redirect(url_for('my_account'))
    except Exception as e:
        conn.rollback()
        flash(f"Error processing purchase: {e}", "error")
        return redirect(url_for('artwork_detail', artwork_id=artwork_id))
    finally:
        cur.close()
        conn.close()


# --- Public-Facing Routes ---
@app.route('/')
def index():
    """Home page with featured artworks and events"""
    conn = get_db_connection()
    if not conn:
        return render_template('index.html', featured_artworks=[], upcoming_events=[])

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Get featured artworks
    cur.execute('''
        SELECT a.*, ar.name as artist_name
        FROM artworks a
        LEFT JOIN artists ar ON a.artist_id = ar.id
        WHERE a.is_featured = TRUE
        ORDER BY a.created_at DESC
        LIMIT 6
    ''')
    featured_artworks = cur.fetchall()

    # Get upcoming events
    cur.execute('''
        SELECT * FROM events
        WHERE is_active = TRUE AND event_date >= CURRENT_DATE
        ORDER BY event_date ASC
        LIMIT 3
    ''')
    upcoming_events = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('index.html',
                         featured_artworks=featured_artworks,
                         upcoming_events=upcoming_events)

@app.route('/gallery')
def gallery():
    """Gallery page with all artworks and filtering"""
    conn = get_db_connection()
    if not conn:
        return render_template('gallery.html', artworks=[], artists=[])

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Get filter parameters
    artist_filter = request.args.get('artist', '')
    year_filter = request.args.get('year', '')
    medium_filter = request.args.get('medium', '')

    # Build query with filters
    query = '''
        SELECT a.*, ar.name as artist_name
        FROM artworks a
        LEFT JOIN artists ar ON a.artist_id = ar.id
        WHERE 1=1
    '''
    params = []

    if artist_filter:
        query += ' AND ar.name ILIKE %s'
        params.append(f'%{artist_filter}%')

    if year_filter:
        query += ' AND a.year_created = %s'
        params.append(year_filter)

    if medium_filter:
        query += ' AND a.medium ILIKE %s'
        params.append(f'%{medium_filter}%')

    query += ' ORDER BY a.created_at DESC'

    cur.execute(query, params)
    artworks = cur.fetchall()

    # Get all artists for filter dropdown
    cur.execute('SELECT id, name FROM artists ORDER BY name')
    artists = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('gallery.html', artworks=artworks, artists=artists)

@app.route('/artwork/<int:artwork_id>')
def artwork_detail(artwork_id):
    """Artwork detail page"""
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'error')
        return redirect(url_for('gallery'))

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Get artwork details
    cur.execute('''
        SELECT a.*, ar.name as artist_name, ar.biography, ar.birth_year, ar.death_year, ar.nationality
        FROM artworks a
        LEFT JOIN artists ar ON a.artist_id = ar.id
        WHERE a.id = %s
    ''', (artwork_id,))
    artwork = cur.fetchone()

    if not artwork:
        flash('Artwork not found', 'error')
        return redirect(url_for('gallery'))

    # Get other works by the same artist
    cur.execute('''
        SELECT a.* FROM artworks a
        WHERE a.artist_id = %s AND a.id != %s
        ORDER BY a.year_created DESC
        LIMIT 4
    ''', (artwork['artist_id'], artwork_id))
    related_works = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('artwork_detail.html', artwork=artwork, related_works=related_works)

@app.route('/artists')
def artists():
    """Artists page"""
    conn = get_db_connection()
    if not conn:
        return render_template('artists.html', artists=[])

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Get all artists with artwork count
    cur.execute('''
        SELECT ar.*, COUNT(a.id) as artwork_count
        FROM artists ar
        LEFT JOIN artworks a ON ar.id = a.artist_id
        GROUP BY ar.id
        ORDER BY ar.name
    ''')
    artists_list = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('artists.html', artists=artists_list)

@app.route('/artist/<int:artist_id>')
def artist_detail(artist_id):
    """Artist detail page"""
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'error')
        return redirect(url_for('artists'))

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Get artist details
    cur.execute('SELECT * FROM artists WHERE id = %s', (artist_id,))
    artist = cur.fetchone()

    if not artist:
        flash('Artist not found', 'error')
        return redirect(url_for('artists'))

    # Get artist's artworks
    cur.execute('''
        SELECT * FROM artworks
        WHERE artist_id = %s
        ORDER BY year_created DESC
    ''', (artist_id,))
    artworks = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('artist_detail.html', artist=artist, artworks=artworks)

@app.route('/events')
def events():
    """Events page"""
    conn = get_db_connection()
    if not conn:
        return render_template('events.html', events=[])

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Get active events
    cur.execute('''
        SELECT * FROM events
        WHERE is_active = TRUE
        ORDER BY event_date ASC
    ''')
    events_list = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('events.html', events=events_list)

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

# --- Admin Routes ---
@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    conn = get_db_connection()
    if not conn:
        return render_template('admin_dashboard.html', stats={})

    cur = conn.cursor()

    # Get statistics
    stats = {}
    cur.execute('SELECT COUNT(*) FROM artworks')
    stats['artworks'] = cur.fetchone()[0]

    cur.execute('SELECT COUNT(*) FROM artists')
    stats['artists'] = cur.fetchone()[0]

    cur.execute('SELECT COUNT(*) FROM events WHERE is_active = TRUE')
    stats['events'] = cur.fetchone()[0]

    cur.execute('SELECT COUNT(*) FROM users')
    stats['users'] = cur.fetchone()[0]

    cur.close()
    conn.close()

    return render_template('admin_dashboard.html', stats=stats)

@app.route('/admin/add_artist', methods=['GET', 'POST'])
@admin_required
def add_artist():
    """Admin route to add a new artist (not necessarily linked to a user)."""
    if request.method == 'POST':
        name = request.form['name']
        biography = request.form.get('biography')
        birth_year = request.form.get('birth_year')
        death_year = request.form.get('death_year')
        nationality = request.form.get('nationality')

        form_data = {
            'name': name, 'biography': biography, 'birth_year': birth_year,
            'death_year': death_year, 'nationality': nationality
        }

        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = str(uuid.uuid4()) + '_' + filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                image_url = f'/static/uploads/{unique_filename}'
            elif file.filename != '':
                flash('Invalid image file type. Allowed: png, jpg, jpeg, gif, webp.', 'error')
                return render_template('add_artist.html', **form_data)

        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'error')
            return render_template('add_artist.html', **form_data)

        cur = conn.cursor()
        try:
            cur.execute('''
                INSERT INTO artists (user_id, name, biography, birth_year, death_year, nationality, image_url)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (
                None, # No user_id for admin-created artist (unless modified to link)
                name,
                biography,
                int(birth_year) if birth_year else None,
                int(death_year) if death_year else None,
                nationality,
                image_url
            ))
            conn.commit()
            flash(f'Artist "{name}" added successfully!', 'success')
            return redirect(url_for('manage_artists'))
        except psycopg2.IntegrityError as e:
            conn.rollback()
            if "artists_name_key" in str(e): # Check for unique name constraint
                flash('An artist with this name already exists.', 'error')
            else:
                flash(f'Database error: {e}. Ensure all unique fields are valid.', 'error')
            return render_template('add_artist.html', **form_data)
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'error')
            return render_template('add_artist.html', **form_data)
        finally:
            cur.close()
            conn.close()

    return render_template('add_artist.html')


@app.route('/admin/add_artwork', methods=['GET', 'POST'])
@admin_required
def add_artwork():
    """Admin route to add a new artwork."""
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'error')
        return redirect(url_for('admin_dashboard'))

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute('SELECT id, name FROM artists ORDER BY name')
    artists_list = cur.fetchall()

    if request.method == 'POST':
        title = request.form['title']
        artist_id = request.form.get('artist_id')
        description = request.form.get('description')
        medium = request.form.get('medium')
        year_created = request.form.get('year_created')
        dimensions = request.form.get('dimensions')
        price = request.form.get('price')
        is_featured = 'is_featured' in request.form

        form_data = {
            'artists': artists_list, 'title': title, 'artist_id': artist_id,
            'description': description, 'medium': medium, 'year_created': year_created,
            'dimensions': dimensions, 'price': price, 'is_featured': is_featured
        }

        if not price or not price.replace('.', '', 1).isdigit():
            flash('Price is required and must be a valid number.', 'error')
            return render_template('add_artwork.html', **form_data)

        if float(price) < 0:
            flash('Price cannot be negative.', 'error')
            return render_template('add_artwork.html', **form_data)


        artwork_image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = str(uuid.uuid4()) + '_' + filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                artwork_image_url = f'/static/uploads/{unique_filename}'
            elif file.filename != '':
                flash('Invalid image file type. Allowed: png, jpg, jpeg, gif, webp.', 'error')
                return render_template('add_artwork.html', **form_data)
            else:
                flash('Artwork image is required.', 'error')
                return render_template('add_artwork.html', **form_data)
        else:
            flash('Artwork image is required.', 'error')
            return render_template('add_artwork.html', **form_data)

        try:
            cur.execute('''
                INSERT INTO artworks (title, artist_id, description, medium, year_created, dimensions, image_url, price, is_featured)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                title,
                int(artist_id) if artist_id else None,
                description,
                medium,
                int(year_created) if year_created else None,
                dimensions,
                artwork_image_url,
                float(price),
                is_featured
            ))
            conn.commit()
            flash(f'Artwork "{title}" added successfully!', 'success')
            return redirect(url_for('manage_artworks'))
        except psycopg2.IntegrityError as e:
            conn.rollback()
            flash(f'Error adding artwork: {e}. Ensure artist is selected and data is valid.', 'error')
            return render_template('add_artwork.html', **form_data)
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'error')
            return render_template('add_artwork.html', **form_data)
        finally:
            cur.close()
            conn.close()

    # For GET request
    cur.close()
    conn.close()
    return render_template('add_artwork.html', artists=artists_list)

@app.route('/admin/add_event', methods=['GET', 'POST'])
@admin_required
def add_event():
    """Admin route to add a new event."""
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description')
        event_date_str = request.form.get('event_date')
        end_date_str = request.form.get('end_date')
        location = request.form.get('location')
        ticket_price = request.form.get('ticket_price')
        is_active = 'is_active' in request.form

        form_data = {
            'title': title, 'description': description, 'event_date': event_date_str,
            'end_date': end_date_str, 'location': location, 'ticket_price': ticket_price,
            'is_active': is_active
        }

        event_date = datetime.strptime(event_date_str, '%Y-%m-%d').date() if event_date_str else None
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() if end_date_str else None

        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = str(uuid.uuid4()) + '_' + filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                image_url = f'/static/uploads/{unique_filename}'
            elif file.filename != '':
                flash('Invalid image file type. Allowed: png, jpg, jpeg, gif, webp.', 'error')
                return render_template('add_event.html', **form_data)

        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'error')
            return render_template('add_event.html', **form_data)

        cur = conn.cursor()
        try:
            cur.execute('''
                INSERT INTO events (title, description, event_date, end_date, location, ticket_price, image_url, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                title,
                description,
                event_date,
                end_date,
                location,
                float(ticket_price) if ticket_price else None,
                image_url,
                is_active
            ))
            conn.commit()
            flash(f'Event "{title}" added successfully!', 'success')
            return redirect(url_for('manage_events'))
        except psycopg2.Error as e:
            conn.rollback()
            flash(f'Error adding event: {e}', 'error')
            return render_template('add_event.html', **form_data)
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'error')
            return render_template('add_event.html', **form_data)
        finally:
            cur.close()
            conn.close()

    return render_template('add_event.html')

@app.route('/admin/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    """Admin route to add a new user."""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form.get('role', 'visitor')

        form_data = {'username': username, 'email': email, 'role': role}

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('add_user.html', **form_data)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('add_user.html', **form_data)

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'error')
            return render_template('add_user.html', **form_data)

        cur = conn.cursor()
        try:
            cur.execute('''
                INSERT INTO users (username, email, password_hash, role)
                VALUES (%s, %s, %s, %s)
            ''', (username, email, password_hash, role))
            conn.commit()
            flash(f'User "{username}" ({role}) added successfully!', 'success')
            return redirect(url_for('manage_users'))
        except psycopg2.IntegrityError as e:
            conn.rollback()
            if "users_username_key" in str(e):
                flash('Username already exists.', 'error')
            elif "users_email_key" in str(e):
                flash('Email already exists.', 'error')
            else:
                flash(f'Database error: {e}', 'error')
            return render_template('add_user.html', **form_data)
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'error')
            return render_template('add_user.html', **form_data)
        finally:
            cur.close()
            conn.close()

    return render_template('add_user.html')

@app.route('/admin/manage_artworks')
@admin_required
def manage_artworks():
    """Admin route to view all artworks in a list."""
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'error')
        return redirect(url_for('admin_dashboard'))

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('''
        SELECT a.id, a.title, ar.name as artist_name, a.year_created, a.is_featured, a.image_url, a.price
        FROM artworks a
        LEFT JOIN artists ar ON a.artist_id = ar.id
        ORDER BY a.created_at DESC
    ''')
    artworks = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('manage_artworks.html', artworks=artworks)

@app.route('/admin/manage_artists')
@admin_required
def manage_artists():
    """Admin route to view all artists in a list."""
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'error')
        return redirect(url_for('admin_dashboard'))

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('''
        SELECT id, name, nationality, birth_year, death_year, image_url
        FROM artists
        ORDER BY name ASC
    ''')
    artists_list = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('manage_artists.html', artists=artists_list)

@app.route('/admin/manage_events')
@admin_required
def manage_events():
    """Admin route to view all events in a list."""
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'error')
        return redirect(url_for('admin_dashboard'))

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('''
        SELECT id, title, event_date, end_date, location, ticket_price, is_active, image_url
        FROM events
        ORDER BY event_date DESC
    ''')
    events_list = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('manage_events.html', events=events_list)

@app.route('/admin/manage_users')
@admin_required
def manage_users():
    """Admin route to view all users in a list."""
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'error')
        return redirect(url_for('admin_dashboard'))

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('''
        SELECT id, username, email, role, created_at
        FROM users
        ORDER BY created_at DESC
    ''')
    users_list = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('manage_users.html', users=users_list)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)