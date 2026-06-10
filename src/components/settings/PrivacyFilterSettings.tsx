import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { privacyFilterApi, PrivacyFilterConfig, PrivacyFilterStatus } from '@/lib/api/privacy-filter';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Loader2, CheckCircle2, XCircle, AlertCircle } from 'lucide-react';
import { toast } from 'sonner';
import { Textarea } from '@/components/ui/textarea';

export function PrivacyFilterSettings() {
  const { t } = useTranslation();
  const [config, setConfig] = useState<PrivacyFilterConfig>({ enabled: false, port: 18088 });
  const [status, setStatus] = useState<PrivacyFilterStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [testText, setTestText] = useState('');
  const [testResult, setTestResult] = useState('');
  const [testing, setTesting] = useState(false);

  // 加载配置和状态
  useEffect(() => {
    loadConfig();
    loadStatus();
    const interval = setInterval(loadStatus, 3000); // 每3秒更新状态
    return () => clearInterval(interval);
  }, []);

  const loadConfig = async () => {
    try {
      const cfg = await privacyFilterApi.getConfig();
      setConfig(cfg);
    } catch (error) {
      console.error('Failed to load privacy filter config:', error);
    }
  };

  const loadStatus = async () => {
    try {
      const st = await privacyFilterApi.getStatus();
      setStatus(st);
    } catch (error) {
      console.error('Failed to load privacy filter status:', error);
    }
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      await privacyFilterApi.setConfig(config);
      toast.success(t('privacyFilter.saveSuccess'));
      await loadStatus();
    } catch (error) {
      toast.error(t('privacyFilter.saveFailed') + ': ' + String(error));
    } finally {
      setLoading(false);
    }
  };

  const handleTest = async () => {
    if (!testText.trim()) {
      toast.error(t('privacyFilter.testTextEmpty'));
      return;
    }

    setTesting(true);
    setTestResult('');
    try {
      const result = await privacyFilterApi.test(testText);
      setTestResult(result);
      toast.success(t('privacyFilter.testSuccess'));
    } catch (error) {
      toast.error(t('privacyFilter.testFailed') + ': ' + String(error));
    } finally {
      setTesting(false);
    }
  };

  const getStatusBadge = () => {
    if (!status) return null;

    if (status.running && status.healthy) {
      return (
        <Badge variant="default" className="gap-1">
          <CheckCircle2 className="h-3 w-3" />
          {t('privacyFilter.statusRunning')}
        </Badge>
      );
    }

    if (status.running && !status.healthy) {
      return (
        <Badge variant="destructive" className="gap-1">
          <AlertCircle className="h-3 w-3" />
          {t('privacyFilter.statusUnhealthy')}
        </Badge>
      );
    }

    return (
      <Badge variant="secondary" className="gap-1">
        <XCircle className="h-3 w-3" />
        {t('privacyFilter.statusStopped')}
      </Badge>
    );
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('privacyFilter.title')}</CardTitle>
              <CardDescription>{t('privacyFilter.description')}</CardDescription>
            </div>
            {getStatusBadge()}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 启用开关 */}
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="privacy-enabled">{t('privacyFilter.enableLabel')}</Label>
              <p className="text-sm text-muted-foreground">
                {t('privacyFilter.enableDescription')}
              </p>
            </div>
            <Switch
              id="privacy-enabled"
              checked={config.enabled}
              onCheckedChange={(checked) => setConfig({ ...config, enabled: checked })}
            />
          </div>

          {/* 端口配置 */}
          <div className="space-y-2">
            <Label htmlFor="privacy-port">{t('privacyFilter.portLabel')}</Label>
            <Input
              id="privacy-port"
              type="number"
              min="1024"
              max="65535"
              value={config.port}
              onChange={(e) => setConfig({ ...config, port: parseInt(e.target.value) || 18088 })}
              className="max-w-xs"
            />
            <p className="text-sm text-muted-foreground">
              {t('privacyFilter.portDescription')}
            </p>
          </div>

          {/* 保存按钮 */}
          <Button onClick={handleSave} disabled={loading}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t('common.save')}
          </Button>
        </CardContent>
      </Card>

      {/* 测试功能 */}
      <Card>
        <CardHeader>
          <CardTitle>{t('privacyFilter.testTitle')}</CardTitle>
          <CardDescription>{t('privacyFilter.testDescription')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="test-input">{t('privacyFilter.testInputLabel')}</Label>
            <Textarea
              id="test-input"
              value={testText}
              onChange={(e) => setTestText(e.target.value)}
              placeholder={t('privacyFilter.testInputPlaceholder')}
              rows={3}
            />
          </div>

          <Button onClick={handleTest} disabled={testing || !status?.running} variant="secondary">
            {testing && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t('privacyFilter.testButton')}
          </Button>

          {testResult && (
            <div className="space-y-2">
              <Label>{t('privacyFilter.testResultLabel')}</Label>
              <div className="rounded-md bg-muted p-3 text-sm">
                {testResult}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
