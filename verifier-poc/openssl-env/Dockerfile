FROM python:3.8

ADD requirements.txt .
RUN pip3 install -r requirements.txt

ADD main.py .
ADD openssl-env/main.sh .
CMD ["./main.sh"]
