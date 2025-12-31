use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. 创建表
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    // ID: UUID类型 + 主键 + 默认值(gen_random_uuid)
                    .col(
                        ColumnDef::new(Users::Id)
                            .uuid()
                            .not_null()
                            .primary_key()
                            .default(Expr::cust("gen_random_uuid()")), 
                    )
                    .col(ColumnDef::new(Users::Username).string().not_null().unique_key())
                    .col(ColumnDef::new(Users::PasswordHash).string().not_null())
                    .col(ColumnDef::new(Users::Phone).string().unique_key()) // 唯一索引
                    .col(ColumnDef::new(Users::Role).string().not_null().default("user"))
                    .col(ColumnDef::new(Users::IsActive).boolean().not_null().default(true))
                    // CreatedAt: 默认当前时间
                    .col(
                        ColumnDef::new(Users::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    // UpdatedAt: 默认当前时间 (配合下方触发器自动更新)
                    .col(
                        ColumnDef::new(Users::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // 2. 创建函数 (用于更新时间戳)
        let db = manager.get_connection();
        db.execute_unprepared(
            "CREATE OR REPLACE FUNCTION update_timestamp()
             RETURNS TRIGGER AS $$
             BEGIN
                 NEW.updated_at = NOW();
                 RETURN NEW;
             END;
             $$ language 'plpgsql';",
        )
        .await?;

        // 3. 创建触发器 (绑定到 users 表)
        db.execute_unprepared(
            "CREATE TRIGGER set_timestamp
             BEFORE UPDATE ON users
             FOR EACH ROW
             EXECUTE PROCEDURE update_timestamp();",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除顺序：触发器 -> 函数 -> 表
        let db = manager.get_connection();
        db.execute_unprepared("DROP TRIGGER IF EXISTS set_timestamp ON users;").await?;
        db.execute_unprepared("DROP FUNCTION IF EXISTS update_timestamp;").await?;

        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Username,
    PasswordHash,
    Phone,
    Role,
    IsActive,
    CreatedAt,
    UpdatedAt,
}