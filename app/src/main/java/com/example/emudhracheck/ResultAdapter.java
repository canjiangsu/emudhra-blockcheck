package com.example.emudhracheck;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;
import com.example.emudhracheck.verify.VerificationResult;
import java.util.List;

/** 结果列表：每行显示 CA 名称、状态（颜色区分）与简短原因。 */
public final class ResultAdapter extends BaseAdapter {

    private final Context context;
    private final List<VerificationResult> results;

    public ResultAdapter(Context context, List<VerificationResult> results) {
        this.context = context;
        this.results = results;
    }

    @Override
    public int getCount() {
        return results.size();
    }

    @Override
    public VerificationResult getItem(int position) {
        return results.get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View view = convertView;
        if (view == null) {
            view = LayoutInflater.from(context).inflate(R.layout.item_result, parent, false);
            Holder holder = new Holder();
            holder.name = view.findViewById(R.id.result_name);
            holder.status = view.findViewById(R.id.result_status);
            holder.detail = view.findViewById(R.id.result_detail);
            view.setTag(holder);
        }
        Holder holder = (Holder) view.getTag();
        VerificationResult result = results.get(position);
        holder.name.setText(result.name);
        holder.status.setText(result.status.label);
        holder.status.setTextColor(statusColor(result.status));
        holder.detail.setText(result.detail);
        return view;
    }

    @SuppressWarnings("deprecation")
    private int statusColor(VerificationResult.Status status) {
        int colorRes;
        switch (status) {
            case BLOCKED:
                colorRes = R.color.status_blocked;
                break;
            case NOT_BLOCKED:
                colorRes = R.color.status_not_blocked;
                break;
            case ROOT_UNTRUSTED:
                colorRes = R.color.status_root_untrusted;
                break;
            default:
                colorRes = R.color.status_error;
                break;
        }
        return context.getResources().getColor(colorRes);
    }

    private static final class Holder {
        TextView name;
        TextView status;
        TextView detail;
    }
}
