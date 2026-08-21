# 通用 RBAC3 权限管理中台

## 目录

```text
rbac-platform/
├── common/              # JWT、统一响应、鉴权上下文
├── auth-service/        # 登录、刷新、下线、Token 黑白名单
├── permission-service/  # 用户、角色、权限、角色继承、职责分离
├── gateway-service/     # Spring Cloud Gateway GlobalFilter
├── db/schema.sql        # MySQL 表结构与初始化数据
├── docker-compose.yml   # MySQL、Redis、RabbitMQ、Sentinel 控制台
└── docs/
    ├── architecture.md # 详细架构设计
    ├── business-closure.md # 业务闭环设计与开发演进
    └── pitfalls.md      # 开发过程中的问题与解决方案
```

## 启动

```bash
docker compose up -d
mvn clean install
mvn -pl auth-service spring-boot:run
mvn -pl permission-service spring-boot:run
mvn -pl gateway-service spring-boot:run
```

默认测试账号：`admin / password`。生产环境必须通过环境变量覆盖 JWT 密钥、数据库密码和 RabbitMQ 凭证，并替换默认 BCrypt 密码。
