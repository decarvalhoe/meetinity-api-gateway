from __future__ import annotations

from locust import HttpUser, between, task


class ApiGatewayUser(HttpUser):
    wait_time = between(0.2, 1.0)

    def on_start(self):
        response = self.client.post(
            "/api/auth/session",
            json={"email": "loadtest@meetinity.io", "password": "secret"},
            name="auth:login",
        )
        if response.ok:
            token = response.json().get("token")
            if token:
                self.client.headers.update({"Authorization": f"Bearer {token}"})

    @task(4)
    def get_users(self):
        self.client.get("/api/users", name="users:list")

    @task(2)
    def get_profile(self):
        self.client.get("/api/profile/me", name="profile:me")

    @task(1)
    def update_profile(self):
        payload = {"display_name": "Load Test", "timezone": "UTC"}
        self.client.put("/api/profile/me", json=payload, name="profile:update")
