/* eslint-disable no-console */
'use client';

import { Clock } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';

import type { PlayRecord } from '@/lib/db.client';
import {
  clearAllPlayRecords,
  getAllPlayRecords,
  subscribeToDataUpdates,
} from '@/lib/db.client';
import { getAllFavorites } from '@/lib/db.client';
import {
  type WatchingUpdate,
  checkWatchingUpdates,
  getDetailedWatchingUpdates,
  subscribeToWatchingUpdatesEvent,
} from '@/lib/watching-updates';

import CapsuleSwitch from '@/components/CapsuleSwitch';
import ScrollableRow from '@/components/ScrollableRow';
import SectionTitle from '@/components/SectionTitle';
import VideoCard from '@/components/VideoCard';

interface ContinueWatchingProps {
  className?: string;
}

export default function ContinueWatching({ className }: ContinueWatchingProps) {
  const [playRecords, setPlayRecords] = useState<
    (PlayRecord & { key: string })[]
  >([]);
  const [loading, setLoading] = useState(true);
  const [watchingUpdates, setWatchingUpdates] = useState<WatchingUpdate | null>(
    null
  );
  const [sortBy, setSortBy] = useState<'recent' | 'progress' | 'favorite'>(
    'recent'
  );
  const [favoriteKeys, setFavoriteKeys] = useState<Set<string>>(new Set());
  const [filterBy, setFilterBy] = useState<
    'all' | 'updated' | 'favorite' | 'progress10'
  >('all');

  // 本地存储键
  const CW_SORT_KEY = 'cw_sort_by';
  const CW_FILTER_KEY = 'cw_filter_by';

  // 初始加载已保存的偏好
  useEffect(() => {
    try {
      const savedSort = localStorage.getItem(CW_SORT_KEY);
      if (
        savedSort === 'recent' ||
        savedSort === 'progress' ||
        savedSort === 'favorite'
      ) {
        setSortBy(savedSort as 'recent' | 'progress' | 'favorite');
      }
    } catch (err) {
      console.debug('ContinueWatching: 读取排序偏好失败', err);
    }
    try {
      const savedFilter = localStorage.getItem(CW_FILTER_KEY);
      if (
        savedFilter === 'all' ||
        savedFilter === 'updated' ||
        savedFilter === 'favorite' ||
        savedFilter === 'progress10'
      ) {
        setFilterBy(
          savedFilter as 'all' | 'updated' | 'favorite' | 'progress10'
        );
      }
    } catch (err) {
      console.debug('ContinueWatching: 读取筛选偏好失败', err);
    }
  }, []);

  // 变更时写入本地存储
  useEffect(() => {
    try {
      localStorage.setItem(CW_SORT_KEY, sortBy);
    } catch (err) {
      console.debug('ContinueWatching: 写入排序偏好失败', err);
    }
  }, [sortBy]);
  useEffect(() => {
    try {
      localStorage.setItem(CW_FILTER_KEY, filterBy);
    } catch (err) {
      console.debug('ContinueWatching: 写入筛选偏好失败', err);
    }
  }, [filterBy]);

  // 处理播放记录数据更新的函数
  const updatePlayRecords = (allRecords: Record<string, PlayRecord>) => {
    // 将记录转换为数组并根据 save_time 由近到远排序
    const recordsArray = Object.entries(allRecords).map(([key, record]) => ({
      ...record,
      key,
    }));

    // 按 save_time 降序排序（最新的在前面）
    const sortedRecords = recordsArray.sort(
      (a, b) => b.save_time - a.save_time
    );

    setPlayRecords(sortedRecords);
  };

  useEffect(() => {
    const fetchPlayRecords = async () => {
      try {
        setLoading(true);

        // 从缓存或API获取所有播放记录
        const allRecords = await getAllPlayRecords();
        updatePlayRecords(allRecords);
        // 获取收藏，供排序使用
        try {
          const favs = await getAllFavorites();
          const favSet = new Set(Object.keys(favs || {}));
          setFavoriteKeys(favSet);
        } catch (err) {
          console.debug('ContinueWatching: 获取收藏失败', err);
        }
      } catch (error) {
        console.error('获取播放记录失败:', error);
        setPlayRecords([]);
      } finally {
        setLoading(false);
      }
    };

    fetchPlayRecords();

    // 监听播放记录更新事件
    const unsubscribe = subscribeToDataUpdates(
      'playRecordsUpdated',
      (newRecords: Record<string, PlayRecord>) => {
        updatePlayRecords(newRecords);
      }
    );

    return unsubscribe;
  }, []);

  // 获取watching updates数据（仅当有播放记录时）
  useEffect(() => {
    // 只有在有播放记录时才检查更新
    if (loading || playRecords.length === 0) {
      return;
    }

    const updateWatchingUpdates = async () => {
      console.log('ContinueWatching: 开始获取更新数据...');

      // 先尝试从缓存加载（快速显示）
      let updates = getDetailedWatchingUpdates();
      console.log('ContinueWatching: 缓存数据:', updates);

      if (updates) {
        setWatchingUpdates(updates);
        console.log('ContinueWatching: 使用缓存数据');
      }

      // 如果缓存为空，主动检查一次
      if (!updates) {
        console.log('ContinueWatching: 缓存为空，主动检查更新...');
        try {
          await checkWatchingUpdates();
          updates = getDetailedWatchingUpdates();
          setWatchingUpdates(updates);
          console.log('ContinueWatching: 主动检查完成，获得数据:', updates);
        } catch (error) {
          console.error('ContinueWatching: 主动检查更新失败:', error);
        }
      }
    };

    // 初始加载
    updateWatchingUpdates();

    // 🔧 优化：订阅播放记录更新事件，实时同步数据
    const unsubscribePlayRecords = subscribeToDataUpdates(
      'playRecordsUpdated',
      (newRecords: Record<string, PlayRecord>) => {
        console.log('ContinueWatching: 收到播放记录更新事件，立即同步数据');
        updatePlayRecords(newRecords);
      }
    );

    // 订阅watching updates事件
    const unsubscribeWatchingUpdates = subscribeToWatchingUpdatesEvent(() => {
      console.log('ContinueWatching: 收到watching updates更新事件');
      const updates = getDetailedWatchingUpdates();
      setWatchingUpdates(updates);
    });

    return () => {
      unsubscribePlayRecords();
      unsubscribeWatchingUpdates();
    };
  }, [loading, playRecords.length]); // 依赖播放记录加载状态

  const hasRecords = !loading && playRecords.length > 0;

  // 计算播放进度百分比
  const getProgress = (record: PlayRecord) => {
    if (record.total_time === 0) return 0;
    return (record.play_time / record.total_time) * 100;
  };

  // 过滤后的记录
  const filteredRecords = useMemo(() => {
    let arr = [...playRecords];
    if (filterBy === 'updated') {
      arr = arr.filter((r) => getNewEpisodesCount(r) > 0);
    } else if (filterBy === 'favorite') {
      arr = arr.filter((r) => favoriteKeys.has(r.key));
    } else if (filterBy === 'progress10') {
      arr = arr.filter((r) => getProgress(r) >= 10);
    }
    return arr;
  }, [playRecords, filterBy, favoriteKeys, getNewEpisodesCount]);

  // 排序后的记录
  const sortedRecords = useMemo(() => {
    const arr = [...filteredRecords];
    if (sortBy === 'recent') {
      return arr.sort((a, b) => b.save_time - a.save_time);
    }
    if (sortBy === 'progress') {
      return arr.sort((a, b) => getProgress(b) - getProgress(a));
    }
    // favorite: 收藏优先，其次按最近
    return arr.sort((a, b) => {
      const af = favoriteKeys.has(a.key) ? 1 : 0;
      const bf = favoriteKeys.has(b.key) ? 1 : 0;
      if (af !== bf) return bf - af;
      return b.save_time - a.save_time;
    });
  }, [filteredRecords, sortBy, favoriteKeys]);

  // 从 key 中解析 source 和 id
  const parseKey = (key: string) => {
    const [source, id] = key.split('+');
    return { source, id };
  };

  // 检查播放记录是否有新集数更新
  const getNewEpisodesCount = useCallback(
    (record: PlayRecord & { key: string }): number => {
      if (!watchingUpdates || !watchingUpdates.updatedSeries) return 0;

      const { source, id } = parseKey(record.key);

      // 在watchingUpdates中查找匹配的剧集
      const matchedSeries = watchingUpdates.updatedSeries.find(
        (series) =>
          series.sourceKey === source &&
          series.videoId === id &&
          series.hasNewEpisode
      );

      return matchedSeries ? matchedSeries.newEpisodes || 0 : 0;
    },
    [watchingUpdates]
  );

  // 获取最新的总集数（用于显示，不修改原始数据）
  const getLatestTotalEpisodes = (
    record: PlayRecord & { key: string }
  ): number => {
    if (!watchingUpdates || !watchingUpdates.updatedSeries)
      return record.total_episodes;

    const { source, id } = parseKey(record.key);

    // 在watchingUpdates中查找匹配的剧集
    const matchedSeries = watchingUpdates.updatedSeries.find(
      (series) => series.sourceKey === source && series.videoId === id
    );

    // 如果找到匹配的剧集且有最新集数信息，返回最新集数；否则返回原始集数
    return matchedSeries && matchedSeries.totalEpisodes
      ? matchedSeries.totalEpisodes
      : record.total_episodes;
  };

  return hasRecords ? (
    <section className={`mb-8 ${className || ''}`}>
      <div className='mb-4 flex items-center justify-between'>
        <SectionTitle
          title='继续观看'
          icon={Clock}
          iconColor='text-green-500'
        />
        {hasRecords && (
          <div className='flex items-center gap-3'>
            {/* 摘要统计 */}
            <div className='text-xs text-gray-600 dark:text-gray-300'>
              共 {playRecords.length} 条 · 有更新{' '}
              {playRecords.filter((r) => getNewEpisodesCount(r) > 0).length} 条
            </div>
            {/* 当前偏好提示 */}
            {(() => {
              const filterLabelMap: Record<string, string> = {
                all: '全部',
                updated: '有更新',
                favorite: '收藏',
                progress10: '进度≥10%',
              };
              const sortLabelMap: Record<string, string> = {
                recent: '最近',
                progress: '进度高',
                favorite: '收藏优先',
              };
              return (
                <div className='text-xs px-2 py-0.5 rounded-full bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-200'>
                  偏好：筛选 {filterLabelMap[filterBy]} · 排序{' '}
                  {sortLabelMap[sortBy]}
                </div>
              );
            })()}
            {/* 筛选 */}
            <CapsuleSwitch
              options={[
                { label: '全部', value: 'all' },
                { label: '有更新', value: 'updated' },
                { label: '收藏', value: 'favorite' },
                { label: '进度≥10%', value: 'progress10' },
              ]}
              active={filterBy}
              onChange={(val) =>
                setFilterBy(
                  val as 'all' | 'updated' | 'favorite' | 'progress10'
                )
              }
            />
            {/* 排序 */}
            <CapsuleSwitch
              options={[
                { label: '最近', value: 'recent' },
                { label: '进度高', value: 'progress' },
                { label: '收藏优先', value: 'favorite' },
              ]}
              active={sortBy}
              onChange={(val) =>
                setSortBy(val as 'recent' | 'progress' | 'favorite')
              }
            />
            {/* 清空按钮 */}
            <button
              className='text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 transition-colors'
              onClick={async () => {
                await clearAllPlayRecords();
                setPlayRecords([]);
              }}
            >
              清空
            </button>
          </div>
        )}
      </div>
      <ScrollableRow>
        {loading
          ? // 加载状态显示灰色占位数据
            Array.from({ length: 6 }).map((_, index) => (
              <div
                key={index}
                className='min-w-[96px] w-24 sm:min-w-[180px] sm:w-44'
              >
                <div className='relative aspect-[2/3] w-full overflow-hidden rounded-lg bg-gray-200 animate-pulse dark:bg-gray-800'>
                  <div className='absolute inset-0 bg-gray-300 dark:bg-gray-700'></div>
                </div>
                <div className='mt-2 h-4 bg-gray-200 rounded animate-pulse dark:bg-gray-800'></div>
                <div className='mt-1 h-3 bg-gray-200 rounded animate-pulse dark:bg-gray-800'></div>
              </div>
            ))
          : // 显示真实数据
            sortedRecords.map((record) => {
              const { source, id } = parseKey(record.key);
              const newEpisodesCount = getNewEpisodesCount(record);
              const latestTotalEpisodes = getLatestTotalEpisodes(record);
              return (
                <div
                  key={record.key}
                  className='min-w-[96px] w-24 sm:min-w-[180px] sm:w-44 relative group/card'
                >
                  <div className='relative group-hover/card:z-[5] transition-all duration-300'>
                    <VideoCard
                      id={id}
                      title={record.title}
                      poster={record.cover}
                      year={record.year}
                      source={source}
                      source_name={record.source_name}
                      progress={getProgress(record)}
                      episodes={latestTotalEpisodes}
                      currentEpisode={record.index}
                      query={record.search_title}
                      from='playrecord'
                      onDelete={() =>
                        setPlayRecords((prev) =>
                          prev.filter((r) => r.key !== record.key)
                        )
                      }
                      type={latestTotalEpisodes > 1 ? 'tv' : ''}
                      remarks={record.remarks}
                    />
                  </div>
                  {/* 新集数徽章 */}
                  {newEpisodesCount > 0 && (
                    <div className='absolute -top-2 -right-2 bg-gradient-to-r from-red-500 to-pink-500 text-white text-xs px-2 py-1 rounded-full shadow-lg z-10'>
                      +{newEpisodesCount}集
                    </div>
                  )}
                  {/* 上次观看时间与进度/集数提示 */}
                  <div className='mt-1 text-[11px] text-gray-600 dark:text-gray-400'>
                    上次观看：
                    {new Date(record.save_time).toLocaleString('zh-CN', {
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </div>
                  <div className='text-[11px] text-gray-600 dark:text-gray-400'>
                    进度：{Math.round(getProgress(record))}% · 第
                    {Math.max(0, record.index)}/{latestTotalEpisodes}集
                  </div>
                </div>
              );
            })}
      </ScrollableRow>
    </section>
  ) : null;
}
