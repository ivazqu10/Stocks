# Setting Up the Project (Windows - Visual Studio Code)

Follow these steps to set up and run the application using the terminal in Visual Studio Code.

## 1. Open Terminal in VS Code

## 2. Create and Activate a Virtual Environment
```sh
python -m venv venv
venv\Scripts\activate
```

## 3. Install Dependencies
```sh
pip install -r requirements.txt
```

## 4. Run the Application
```sh
flask --app app run --debug    
```