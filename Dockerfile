FROM python:3.10.5

RUN pip3 install flask flask_cors flask_jwt_extended requests

EXPOSE 5000

CMD ["bash"]