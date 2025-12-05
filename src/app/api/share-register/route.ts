/* eslint-disable no-console,@typescript-eslint/no-explicit-any */
// @ts-ignore
import { NextRequest, NextResponse } from 'next/server';

import { getConfig, clearConfigCache } from '@/lib/config';
import { db } from '@/lib/db';

// 强制使用动态渲染，避免静态优化
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const revalidate = 0;

// 读取存储类型环境变量，默认 localstorage
const STORAGE_TYPE =
  // @ts-ignore
  (process.env.NEXT_PUBLIC_STORAGE_TYPE as
    | 'localstorage'
    | 'redis'
    | 'upstash'
    | 'kvrocks'
    | undefined) || 'localstorage';

// 生成签名
async function generateSignature(
  data: string,
  secret: string
): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(data);

  // 导入密钥
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // 生成签名
  const signature = await crypto.subtle.sign('HMAC', key, messageData);

  // 转换为十六进制字符串
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// 生成认证Cookie（带签名）
async function generateAuthCookie(
  username?: string,
  password?: string,
  role?: 'owner' | 'admin' | 'user',
  includePassword = false
): Promise<string> {
  const authData: any = { role: role || 'user' };

  // 只在需要时包含 password
  if (includePassword && password) {
    authData.password = password;
  }

  // @ts-ignore process is available in Node.js runtime
  if (username && process.env.PASSWORD) {
    authData.username = username;
    // 使用密码作为密钥对用户名进行签名
    // @ts-ignore process is available in Node.js runtime
    const signature = await generateSignature(username, process.env.PASSWORD);
    authData.signature = signature;
    authData.timestamp = Date.now(); // 添加时间戳防重放攻击
  }

  return encodeURIComponent(JSON.stringify(authData));
}

export async function GET(req: NextRequest) {
  try {
    // localStorage 模式不支持注册
    if (STORAGE_TYPE === 'localstorage') {
      return NextResponse.json(
        { error: 'localStorage 模式不支持用户注册' },
        { status: 400 }
      );
    }

    // @ts-ignore
    const { searchParams } = new URL(req.url);
    const shareKey = searchParams.get('key');

    // 检查是否提供了分享key
    if (!shareKey) {
      return NextResponse.json(
        { error: '缺少分享链接参数' },
        { status: 400 }
      );
    }

    // 从环境变量中获取分享key对应的账号密码
    const shareEnvKey = `SHARE_KEY_${shareKey.toUpperCase()}`;
    // @ts-ignore process is available in Node.js runtime
    const userCredentials = process.env[shareEnvKey];

    if (!userCredentials) {
      return NextResponse.json(
        { error: '无效的分享链接' },
        { status: 400 }
      );
    }

    // 解析账号密码 (格式: username:password)
    const [username, password] = userCredentials.split(':');

    if (!username || !password) {
      return NextResponse.json(
        { error: '分享链接配置错误' },
        { status: 500 }
      );
    }

    try {
      // 检查用户是否已存在
      const userExists = await db.checkUserExist(username);
      if (!userExists) {
        // 用户不存在，进行注册
        await db.registerUser(username, password);

        // 重新获取配置来添加用户
        const config = await getConfig();
        const newUser = {
          username: username,
          role: 'user' as const,
          createdAt: Date.now(), // 设置注册时间戳
        };

        config.UserConfig.Users.push(newUser);

        // 保存更新后的配置
        await db.saveAdminConfig(config);

        // 清除缓存，确保下次获取配置时是最新的
        clearConfigCache();
      }

      // 自动登录
      // 使用环境变量中的SITE_BASE或者默认值来构造重定向URL
      // @ts-ignore
      const siteBase = process.env.SITE_BASE || 'http://localhost:3000';
      const response = NextResponse.redirect(new URL('/', siteBase));
      
      const cookieValue = await generateAuthCookie(
        username,
        password,
        'user',
        false
      );
      const expires = new Date();
      expires.setDate(expires.getDate() + 7); // 7天过期

      response.cookies.set('user_auth', cookieValue, {
        path: '/',
        expires,
        sameSite: 'lax',
        httpOnly: false,
        secure: false,
      });

      return response;
    } catch (err) {
      console.error('注册或登录用户失败', err);
      return NextResponse.json({ error: '操作失败，请稍后重试' }, { status: 500 });
    }
  } catch (error) {
    console.error('分享注册接口异常', error);
    return NextResponse.json({ error: '服务器错误' }, { status: 500 });
  }
}