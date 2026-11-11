package com.example.emudhracheck;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;
import com.example.emudhracheck.expose.ExposedServerState;
import java.util.ArrayList;
import java.util.List;

/** 对外服务端口列表：端口、监听状态、成功/失败计数。 */
public final class ExposedPortAdapter extends BaseAdapter {

    private final Context context;
    private List<ExposedServerState.PortStatus> ports = new ArrayList<>();

    public ExposedPortAdapter(Context context, List<ExposedServerState.PortStatus> initial) {
        this.context = context;
        setPorts(initial);
    }

    public void setPorts(List<ExposedServerState.PortStatus> ports) {
        this.ports = ports == null ? new ArrayList<>() : ports;
        notifyDataSetChanged();
    }

    @Override
    public int getCount() {
        return ports.size();
    }

    @Override
    public ExposedServerState.PortStatus getItem(int position) {
        return ports.get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View view = convertView;
        if (view == null) {
            view = LayoutInflater.from(context).inflate(R.layout.item_exposed_port, parent, false);
            Holder holder = new Holder();
            holder.name = view.findViewById(R.id.expose_name);
            holder.port = view.findViewById(R.id.expose_port);
            holder.state = view.findViewById(R.id.expose_state);
            holder.detail = view.findViewById(R.id.expose_detail);
            view.setTag(holder);
        }
        Holder holder = (Holder) view.getTag();
        ExposedServerState.PortStatus status = ports.get(position);

        holder.name.setText(status.name);
        int port = status.port != 0 ? status.port : status.requestedPort;
        holder.port.setText(context.getString(R.string.expose_port, port));

        if (status.listening) {
            holder.state.setText(R.string.expose_status_listening);
            holder.state.setTextColor(color(R.color.status_blocked));
        } else if (status.error != null) {
            holder.state.setText(R.string.expose_status_failed);
            holder.state.setTextColor(color(R.color.status_not_blocked));
        } else {
            holder.state.setText(R.string.expose_status_idle);
            holder.state.setTextColor(color(R.color.status_error));
        }

        String detail = status.error != null
                ? status.error
                : context.getString(R.string.expose_counters,
                        status.accepted.get(), status.rejected.get(), status.filtered.get());
        holder.detail.setText(detail);
        return view;
    }

    @SuppressWarnings("deprecation")
    private int color(int colorRes) {
        return context.getResources().getColor(colorRes);
    }

    private static final class Holder {
        TextView name;
        TextView port;
        TextView state;
        TextView detail;
    }
}
