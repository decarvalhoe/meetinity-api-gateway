# 🚀 Meetinity API Gateway

## ⚠️ **REPOSITORY ARCHIVED - MOVED TO MONOREPO**

**This repository has been archived and is now read-only.**

### 📍 **New Location**
All development has moved to the **Meetinity monorepo**:

**🔗 https://github.com/decarvalhoe/meetinity**

The API Gateway service is now located at:
```
meetinity/services/api-gateway/
```

### 🔄 **Migration Complete**
- ✅ **All code** has been migrated with complete history
- ✅ **Latest features** including performance testing, monitoring, and security enhancements
- ✅ **CI/CD pipeline** integrated with unified deployment
- ✅ **Documentation** updated and consolidated

### 🛠️ **For Developers**

#### **Clone the monorepo:**
```bash
git clone https://github.com/decarvalhoe/meetinity.git
cd meetinity/services/api-gateway
```

#### **Development workflow:**
```bash
# Start all services
docker compose -f docker-compose.dev.yml up

# API Gateway specific development
cd services/api-gateway
# Your development commands here
```

### 📚 **Documentation**
- **Service Documentation**: `meetinity/services/api-gateway/README.md`
- **Infrastructure Guide**: `meetinity/docs/service-inventory.md`
- **Deployment Guide**: `meetinity/infra/helm/meetinity/`

### 🏗️ **Architecture Benefits**
The monorepo provides:
- **Unified CI/CD** for all Meetinity services
- **Consistent Docker builds** and deployment
- **Centralized configuration** management
- **Simplified dependency** management
- **Cross-service integration** testing

---

**📅 Archived on:** September 29, 2025  
**🔗 Monorepo:** https://github.com/decarvalhoe/meetinity  
**📧 Questions:** Please open issues in the monorepo

---

## 📋 **Original Service Description**

The Meetinity API Gateway was the single entry point for the Meetinity platform, providing flexible routing, security-first design, built-in observability, and performance-ready features including response caching and automated load tests.

**Key features that are now available in the monorepo:**
- Dynamic service discovery and load balancing
- JWT enforcement and CORS policies  
- Prometheus metrics and distributed tracing
- Locust/k6 performance testing scripts
- Security audit checklist and benchmarks
