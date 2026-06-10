// Privacy Filter API 类型定义和封装

export interface PrivacyFilterStatus {
  running: boolean;
  port: number;
  healthy: boolean;
  error: string | null;
}

export interface PrivacyFilterConfig {
  enabled: boolean;
  port: number;
}

export const privacyFilterApi = {
  /**
   * 启动隐私过滤服务
   */
  async start(): Promise<void> {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('start_privacy_filter_service');
  },

  /**
   * 停止隐私过滤服务
   */
  async stop(): Promise<void> {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('stop_privacy_filter_service');
  },

  /**
   * 获取服务状态
   */
  async getStatus(): Promise<PrivacyFilterStatus> {
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<PrivacyFilterStatus>('get_privacy_filter_status');
  },

  /**
   * 测试过滤功能
   */
  async test(text: string): Promise<string> {
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<string>('test_privacy_filter', { testText: text });
  },

  /**
   * 获取配置
   */
  async getConfig(): Promise<PrivacyFilterConfig> {
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<PrivacyFilterConfig>('get_privacy_filter_config');
  },

  /**
   * 设置配置
   */
  async setConfig(config: PrivacyFilterConfig): Promise<void> {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('set_privacy_filter_config', { config });
  },
};
