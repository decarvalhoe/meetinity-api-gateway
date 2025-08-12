# Meetinity API Gateway

Gateway Flask proxying requests to the user service.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env  # update values if needed
python src/app.py
```

## Testing

```bash
pytest
flake8
```

