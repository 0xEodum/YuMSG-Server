from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager
import os

# Обновленный URL с корректными учетными данными
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postpass@localhost:5432/chatdb"
)

# Создаем движок с выводом отладочной информации
engine = create_engine(
    DATABASE_URL,
    echo=True  # Включаем вывод SQL-запросов для отладки
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# Dependency для FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Контекстный менеджер для использования в сервисах
@contextmanager
def get_db_context():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# Функция для инициализации базы данных
def init_db():
    from .models.user import User, UserDevice  # Импортируем все модели

    print(f"Initializing database at: postgresql://postgres:***@localhost:5432/chatdb")
    try:
        # Проверяем наличие таблиц
        inspector = engine.dialect.inspector(engine)
        existing_tables = inspector.get_table_names()
        print(f"Existing tables before creation: {existing_tables}")

        # Создаем таблицы
        Base.metadata.create_all(bind=engine)

        # Проверяем созданные таблицы
        inspector = engine.dialect.inspector(engine)
        tables = inspector.get_table_names()
        print(f"Tables after creation: {tables}")

        print("Database tables created successfully")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        raise