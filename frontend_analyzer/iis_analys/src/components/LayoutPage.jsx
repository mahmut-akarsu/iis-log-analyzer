import React, { useState } from 'react';
import { Layout, Menu } from 'antd';
import { UploadOutlined, FileOutlined, AreaChartOutlined } from '@ant-design/icons';
import CollapseStats from './CollapseStats'; // CollapseStats bileşenini içe aktarın
import LogFileUpload from './LogFileUpload';
import LogFilesHandler from './LogFilesHandler';
import GetGeneralStatsByIndex from './GetGeneralStatsByIndex';

const { Sider, Content } = Layout;

const LayoutPage = () => {
  const [selectedKey, setSelectedKey] = useState('1'); // Başlangıçta "Log Dosyası Yükle" seçili olsun

  const handleMenuClick = ({ key }) => {
    setSelectedKey(key);
  };

  const renderContent = () => {
    switch (selectedKey) {
      case '1':
        return <div><LogFileUpload /></div>; // Log Dosyası Yükle içeriği
      case '2':
        return <LogFilesHandler/>; // Log Dosyaları Listesi içeriği
      case '3':
        return <CollapseStats index_name={localStorage.getItem('selectedIndex')} />; // Grafikler içeriği (CollapseStats)
      case '4':
        return <GetGeneralStatsByIndex index_name={localStorage.getItem('selectedIndex')} />; // Grafikler içeriği (CollapseStats)
      default:
        return <div>Log Dosyası Yükle Sayfası</div>;
    }
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider collapsible>
        <Menu
          theme="dark"
          selectedKeys={[selectedKey]}
          mode="inline"
          onClick={handleMenuClick}
        >
          <Menu.Item key="1" icon={<UploadOutlined />}>
            Log Dosyası Yükle
          </Menu.Item>
          <Menu.Item key="2" icon={<FileOutlined />}>
            Log Dosyaları Listesi
          </Menu.Item>
          <Menu.Item key="3" icon={<AreaChartOutlined />}>
            Grafikler
          </Menu.Item>
          <Menu.Item key="4" icon={<AreaChartOutlined />}>
            Genel İstatisikler
          </Menu.Item>
        </Menu>
      </Sider>
      <Layout className="site-layout">
        <Content style={{ margin: '16px' }}>
          {renderContent()}
        </Content>
      </Layout>
    </Layout>
  );
};

export default LayoutPage;