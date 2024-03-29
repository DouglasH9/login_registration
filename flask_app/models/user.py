from flask_app.config.mysqlconnection import connectToMySQL
from flask_app import app
from flask import flash
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)


class User:
    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @classmethod
    def register_user(cls, data):
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES ( %(fname)s, %(lname)s, %(email)s, %(password)s, NOW(), NOW() )"
        return connectToMySQL('login_register_assignment').query_db(query, data)

    @staticmethod
    def validate_email_reg(data):
        is_valid = True
        query = "SELECT * FROM users WHERE email = %(email)s;"
        results = connectToMySQL('login_register_assignment').query_db(query,data)
        if len(results) > 0:
            flash("Email already taken, soz not soz.")
            is_valid=False
        if len(data['email']) < 4:
            flash('Email must be longer than 3 characters')
            is_valid = False
        if not EMAIL_REGEX.match(data['email']):
            flash('Invalid email address!')
            is_valid = False
        return is_valid

    @classmethod
    def get_by_email(cls, data):
        query = "SELECT * FROM users WHERE email = %(email)s"
        result = connectToMySQL('login_register_assignment').query_db(query, data)
        if len(result)<1:
            return False
        return cls(result[0])

