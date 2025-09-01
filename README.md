MILESTONE 1 ==>



Week 1️⃣ :


This Is The Step-by-Step Guide How I Did The Initial Project Setup :-

1. Install Docker
   
2. Download the DVWA on local system
   (https://github.com/digininja/DVWA)
   
3. Download the JuiceShop on local system
   (git clone https://github.com/juice-shop/juice-shop.git)

4. Run The DVWA  -->  (docker run --rm -it -p 8080:80 vulnerables/web-dvwa)

5. Open browser → http://localhost:8080
	•	Default login:
	•	Username: admin
	•	Password: password


Week 2️⃣ :


Crawler Development Workflow  :-

1. Set Up Environment
    (python3 -m venv crawler_env)
    (source crawler_env/bin/activate)   [did it in my mac system]
    (crawler_env\Scripts\activate)      [For Windows]
    (pip install --upgrade pip)

3. Install Required Libraries  -->  (pip install requests beautifulsoup4 selenium tqdm)

4. Define Target Base URLs
	•	DVWA: http://localhost:8080/
	•	Juice Shop: http://localhost:3000/  [just to test Juice Shop for now]

5. Did The Code Of Crawler.py

6. Tested it by running it
















