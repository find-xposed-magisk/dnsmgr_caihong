<?php
declare (strict_types = 1);

namespace app\lib;

use RuntimeException;
use Swoole\ConnectionPool;
use think\db\ConnectionInterface;
use think\db\PDOConnection;

class NewDbManager extends \think\Db
{
    /**
     * @var array<string, ConnectionPool>
     */
    protected array $pools = [];

    /**
     * @var array<int, string>
     */
    protected array $borrowed = [];

    /**
     * 创建数据库连接实例
     * @access protected
     * @param string|array|null $name  连接标识
     * @param bool        $force 强制重新连接
     * @return ConnectionInterface
     */
    protected function instance(string|array|null $name = null, bool $force = false): ConnectionInterface
    {
        if (empty($name)) {
            $name = $this->getConfig('default', 'mysql');
        }

        return $this->createConnection($name);
    }

    /**
     * 从 Swoole 连接池借出 ThinkPHP 数据库连接，保持 Db 查询链兼容。
     */
    public function pool(string|array|null $name = null, ?float $timeout = null): ConnectionInterface
    {
        if (empty($name)) {
            $name = $this->getConfig('default', 'mysql');
        }

        $key = is_array($name) ? md5(json_encode($name)) : $name;
        $pool = $this->getPool($name, $key);
        $connection = $pool->get($timeout ?? (float) $this->getConfig('pool_timeout', 3));

        if (!$connection instanceof ConnectionInterface) {
            throw new RuntimeException('数据库连接池繁忙，请稍后重试');
        }

        $this->borrowed[spl_object_id($connection)] = $key;

        return $connection;
    }

    /**
     * 归还连接。异常路径传入 $broken=true 时丢弃当前连接并补建新连接。
     */
    public function release(?ConnectionInterface $connection, bool $broken = false): void
    {
        if (!$connection) {
            return;
        }

        $objectId = spl_object_id($connection);
        $key = $this->borrowed[$objectId] ?? null;
        unset($this->borrowed[$objectId]);

        if (!$key || !isset($this->pools[$key])) {
            $connection->close();
            return;
        }

        if ($broken) {
            $connection->close();
            try {
                $this->pools[$key]->put(null);
            } catch (\Throwable $e) {
                // 原始异常更重要，补建连接失败留给下一次获取连接时再暴露。
            }
            return;
        }

        if ($connection instanceof PDOConnection) {
            $connection->free();
        }

        $this->pools[$key]->put($connection);
    }

    /**
     * 关闭所有池，命令进程退出时可显式调用。
     */
    public function closePool(): void
    {
        foreach ($this->pools as $pool) {
            $pool->close();
        }

        $this->pools = [];
        $this->borrowed = [];
    }

    protected function getPool(string|array $name, string $key): ConnectionPool
    {
        if (!isset($this->pools[$key])) {
            $config = is_array($name) ? $name : $this->getConnectionConfig($name);
            $size = (int) ($config['pool_size'] ?? $this->getConfig('pool_size', 32));

            $this->pools[$key] = new ConnectionPool(function () use ($config) {
                return $this->createConnection($config);
            }, $size);
        }

        return $this->pools[$key];
    }
}
