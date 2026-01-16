import mysql.connector
from mysql.connector import Error
import os
from pathlib import Path
from config import config

def init_database():
    """Initialize database with schema"""
    try:
        # Read schema
        schema_path = Path(__file__).parent / 'schema.sql'
        with open(schema_path, 'r') as f:
            schema_sql = f.read()
        
        # Connect to MySQL
        connection = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # Split SQL by semicolon
            sql_commands = schema_sql.split(';')
            
            for command in sql_commands:
                if command.strip():
                    try:
                        cursor.execute(command)
                    except Error as e:
                        print(f"Error executing command: {e}")
                        print(f"Command: {command[:100]}...")
            
            connection.commit()
            print("Database initialized successfully!")
            
    except Error as e:
        print(f"Error: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

if __name__ == "__main__":
    init_database()
