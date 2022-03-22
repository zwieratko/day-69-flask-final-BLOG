from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterUserForm, LoginUserForm, CommentForm
from flask_gravatar import Gravatar
import secrets
from functools import wraps
from typing import Callable
import os

LIST_OF_EDITORS = [1, 2]


class MySQLAlchemy(SQLAlchemy):
    Column: Callable
    Integer: Callable
    String: Callable
    Text: Callable
    ForeignKey: Callable


app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY_BLOG_01')  # secrets.token_urlsafe(32)
print(app.secret_key)
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

# # CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog_new_02.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = MySQLAlchemy(app)

# # INITIALIZE GRAVATAR
gravatar = Gravatar(
    app,
    size=32,
    rating="g",
    default="retro",
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None,
)


# # CONFIGURE TABLES
# Child
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # ? ForeignKey('users.id')
    author = relationship("User", back_populates="posts_list")  # Many
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments_list = relationship("Comment", back_populates="post")  # One (to many Comment author )


# Parent
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)  # One user is linked to many BlogPost / Comment
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts_list = relationship("BlogPost", back_populates="author")  # One ( to many BlogPost author )
    comments_list = relationship("Comment", back_populates="author")  # One (to many Comment author )


# Child
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # ? ForeignKey('users.id')
    author = relationship("User", back_populates="comments_list")  # Many
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))  # ? ForeignKey('blog_posts.id')
    post = relationship("BlogPost", back_populates="comments_list")  # Many


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.context_processor
def inject_current_year():
    return dict(
        current_year_in_footer=date.today().year,
        random_secrets=secrets.token_hex(16),
        list_of_editors=LIST_OF_EDITORS,
    )


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, section_name="- Home")


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterUserForm()
    if register_form.validate_on_submit():
        print("OK. Data from form are valid.")
        if User.query.filter_by(email=register_form.email.data).first() is None:
            new_user = User(
                email=register_form.email.data,
                password=generate_password_hash(register_form.password.data, "pbkdf2:sha256", 16),
                name=register_form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            print("OK. New user successfully created in DB.")
            login_user(User.query.filter_by(email=register_form.email.data).first())
            return redirect(url_for("get_all_posts"))
        else:
            print("NOK. Email already exists!")
            flash("You've already signed up with that email, log in instead, please!")
            return redirect(url_for("login"))
    return render_template("register.html", section_name="- Register", form=register_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginUserForm()
    if login_form.validate_on_submit():
        print("OK. Data from form are valid.")
        if User.query.filter_by(email=login_form.email.data).first() is not None:
            print("OK. Email.")
            hash_from_db = User.query.filter_by(email=login_form.email.data).first().password
            if check_password_hash(hash_from_db, login_form.password.data):
                print("OK. Password.")
                login_user(User.query.filter_by(email=login_form.email.data).first())
                return redirect(url_for("get_all_posts"))
            else:
                print("NOK. Wrong password!")
                flash("Password incorrect, please try again!")
                return redirect(url_for("login"))
        else:
            print("NOK. Wrong email!")
            flash("That email does not exist, please try again!")
            return redirect(url_for("login"))
    return render_template("login.html", section_name="- Login", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    all_comments = Comment.query.filter_by(post_id=post_id).all()
    if comment_form.validate_on_submit():
        print("OK. Data from comment form are valid.")
        if not current_user.is_anonymous:
            print("OK. User is not anonymous. He can make a comment.")
            new_comment = Comment(
                text=comment_form.comment_text.data,
                author=current_user,
                post=requested_post,
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        else:
            print("NOK. User is anonymous.")
            flash("You need to log in or register to comment.")
            return redirect(url_for("login"))
    return render_template(
        "post.html",
        post=requested_post,
        section_name=f"- {requested_post.title}",
        form=comment_form,
        comments=all_comments,
    )


@app.route("/about")
def about():
    return render_template("about.html", section_name="- About")


@app.route("/contact")
def contact():
    return render_template("contact.html", section_name="- Contact")


def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.is_authenticated:
            if int(current_user.id) in LIST_OF_EDITORS:
                return function(*args, **kwargs)
            return abort(403)
        return abort(401)
    return wrapper_function


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,  # !!!
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, is_edit=False)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = post.author  # edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/internal_test")
# @login_required
def internal_test():
    total_record = db.session.query(BlogPost).count()
    for c in BlogPost.__table__.columns:
        print(c.name)
    print("...")
    for c in User.__table__.columns:
        print(c)
    if current_user.is_authenticated:
        all_post = BlogPost.query.filter_by(author_id=current_user.id).all()
        all_post_title_list = [post.title for post in all_post]
        all_used_emails = User.query.all()
        all_used_emails_list = [user.email for user in all_used_emails]
        return f"hmmm..  Total rec.: {total_record} / {current_user.name} <br>" \
               f"{all_post_title_list} <br>" \
               f"{all_used_emails_list}"
    return f"Anonymous user!"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
