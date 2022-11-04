from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm,CommentsForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.app_context().push()
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# gravatar image
gravatar = Gravatar(app,
                    size=25,
                    rating='g',
                    default='wavatar',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
                    




##CONFIGURE TABLES



class Users(db.Model,UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    # user can have many blogs
    posts = relationship("BlogPost", back_populates="auther")
    comments = relationship("PostComment", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # forgein key for one to many rela
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    auther = relationship("Users", back_populates="posts")
    # comments relation
    comments = relationship("PostComment", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

class PostComment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))

    comment_author = relationship("Users", back_populates="comments")
    posts = relationship("BlogPost", back_populates="comments")

db.create_all()
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)        
    return decorated_function

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    
    return render_template("index.html", all_posts=posts,loged=current_user)


@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = db.session.query(Users).filter_by(email=form.email.data).first()
        if user:
            flash('email all ready have an account')
            return redirect(url_for('login'))
        
        new_user = Users(
            email=form.email.data,
            password= generate_password_hash(form.password.data,
            method='pbkdf2:sha256',salt_length=8),
            name=form.name.data,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html",form=form,loged=current_user)


@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(Users).filter_by(email=form.email.data).first()
        if user:
            pas = check_password_hash(user.password,form.password.data)
            if pas:
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Wrong password')
                return redirect(url_for('login'))
        else:
            flash('Email Not Found')
            return redirect(url_for('register'))



    return render_template("login.html",form=form,loged=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=['GET','POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form=CommentsForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = PostComment(
            comment = form.comment.data,
            author_id = current_user.id,
            post_id = requested_post.id,
        )
       
        db.session.add(new_comment)
        db.session.commit()
        return render_template("post.html", post=requested_post,loged=current_user,form=form)
    return render_template("post.html", post=requested_post,loged=current_user,form=form)


@app.route("/about")
def about():
    return render_template("about.html",loged=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html",loged=current_user)


@app.route("/new-post",methods=['GET','POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            # author_id=current_user.id,
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            auther=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form,loged=current_user)


@app.route("/edit-post/<int:post_id>")
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,loged=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
